package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pushbullet/engineer"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/cloud"
	"google.golang.org/cloud/compute/metadata"
	"google.golang.org/cloud/logging"
	"google.golang.org/cloud/storage"
)

var (
	logger  *logging.Client
	appName string
	project string
)

const (
	localStatePath = "/agent/state.json"
	socketPath     = "/tmp/agent/agent.sock"
	appUID         = 2000
)

func log(level logging.Level, prefix string, message string, labels map[string]string) {
	if strings.HasPrefix(message, "http: TLS handshake error from ") {
		// there's a bunch of these caused by HTTPS port scanners, so just discard these in production
		// https://groups.google.com/forum/#!topic/golang-nuts/d4sjZR7H4gU
		return
	}
	printMessage := message
	if level == logging.Error {
		printMessage = "ERROR: " + message
	}
	fmt.Println("[" + prefix + "] " + printMessage)

	if logger == nil {
		return
	}

	hostname, _ := os.Hostname()

	err := logger.Log(logging.Entry{
		Level:   level,
		Payload: fmt.Sprintf("%s[%s]: %s", prefix, hostname, message),
		Labels:  labels,
	})
	if err != nil {
		fmt.Println("logging failed:", err)
	}
}

func infof(f string, args ...interface{}) {
	log(logging.Info, "agent", fmt.Sprintf(f, args...), nil)
}

func errorf(f string, args ...interface{}) {
	log(logging.Error, "agent", fmt.Sprintf(f, args...), nil)
}

func fatal(v interface{}) {
	errorf("%+v", v)
	exit(1)
}

func exit(code int) {
	if logger != nil {
		if err := logger.Flush(); err != nil {
			fmt.Println("failed to flush logs:", err)
		}
	}
	os.Exit(code)
}

func V(err error) {
	if err != nil {
		fatal(err)
	}
}

func WriteFile(path, contents string, perm os.FileMode) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	V(err)
	defer f.Close()
	_, err = f.Write([]byte(contents))
	V(err)
}

func Exists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		}
		V(err)
	}
	return true
}

func sendMessage(msg string) string {
	if Exists(socketPath) {
		sock, err := net.Dial("unix", socketPath)
		V(err)
		_, err = sock.Write([]byte(msg + "\n"))
		V(err)
		r := bufio.NewReader(sock)
		line, err := r.ReadString('\n')
		V(err)
		return strings.TrimSpace(line)
	}
	return ""
}

func Run(command string) {
	fmt.Println("RUN:", command)
	args := strings.Split(command, " ")
	output, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		fmt.Printf("command failed: %s\n output=%s\n", command, output)
		V(err)
	}
}

func RunWithExit(command string) int {
	fmt.Println("RUN:", command)
	args := strings.Split(command, " ")
	output, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			return exiterr.Sys().(syscall.WaitStatus).ExitStatus()
		} else {
			fmt.Printf("command failed: %s\n output=%s\n", command, output)
			V(err)
		}
	}
	return 0
}

func versionDir(version int) string {
	versionName := strconv.Itoa(version)
	return "/agent/" + versionName
}

func fetchVersion(c context.Context, bucketName string, version int) string {
	infof("fetching version %d", version)
	versionName := strconv.Itoa(version)
	dir := versionDir(version)
	tmpDir, err := ioutil.TempDir("", "")
	V(err)

	client, err := storage.NewClient(c)
	V(err)
	bucket := client.Bucket(bucketName)

	if !Exists(dir) {
		infof("reading package")
		r, err := bucket.Object(versionName + "/package.zip").NewReader(c)
		V(err)
		contents, err := ioutil.ReadAll(r)
		V(err)
		z, err := zip.NewReader(bytes.NewReader(contents), int64(len(contents)))
		V(err)

		for _, f := range z.File {
			infof("extracting file %s", f.Name)
			input, err := f.Open()
			V(err)
			output, err := os.OpenFile(tmpDir+"/"+f.Name, os.O_CREATE|os.O_WRONLY, 0644)
			V(err)
			_, err = io.Copy(output, input)
			V(err)
			input.Close()
			output.Close()
		}

		V(os.Rename(tmpDir, dir))
		V(os.Chmod(dir, 0755))
	}

	for _, filename := range []string{"app.json", "env.json"} {
		r, err := bucket.Object(versionName + "/" + filename).NewReader(c)
		V(err)
		contents, err := ioutil.ReadAll(r)
		V(err)
		path := filepath.Join(dir, filename)
		V(ioutil.WriteFile(path, contents, 0644))
	}

	// allow the app to bind low ports as not root
	appJson, err := ioutil.ReadFile(dir + "/app.json")
	V(err)
	app := engineer.App{}
	V(json.Unmarshal(appJson, &app))
	exePath := filepath.Join(dir, filepath.Base(app.Executable))
	V(os.Chmod(exePath, 0755))
	// let executable bind lower ports as non-root user
	V(exec.Command("setcap", "cap_net_bind_service=+ep", exePath).Run())

	return dir
}

type AppProcess struct {
	Command          *exec.Cmd
	Worker           bool
	GracefulShutdown bool
	Exited           chan bool
}

func startVersion(version int) (*AppProcess, error) {
	dir := versionDir(version)

	appJson, err := ioutil.ReadFile(dir + "/app.json")
	if err != nil {
		return nil, err
	}

	app := engineer.App{}
	if err := json.Unmarshal(appJson, &app); err != nil {
		return nil, err
	}

	versionName := strconv.Itoa(version)

	environment := []string{
		"ENGR_APP=" + appName,
		"ENGR_VERSION=" + versionName,
		"ENGR_PROJECT=" + project,
	}

	envJson, err := ioutil.ReadFile(dir + "/env.json")
	if err != nil {
		return nil, err
	}

	env := map[string]string{}
	if err := json.Unmarshal(envJson, &env); err != nil {
		return nil, err
	}

	for k, v := range env {
		environment = append(environment, fmt.Sprintf("%s=%s", k, v))
	}

	cmd := &exec.Cmd{
		Path: filepath.Join(dir, filepath.Base(app.Executable)),
		Dir:  "/tmp",
		Env:  environment,
	}

	ap := &AppProcess{
		Command:          cmd,
		Worker:           app.Worker,
		GracefulShutdown: app.GracefulShutdown,
		Exited:           make(chan bool, 1),
	}

	stdout, err := ap.Command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := ap.Command.StderrPipe()
	if err != nil {
		return nil, err
	}
	err = ap.Command.Start()
	if err != nil {
		return nil, err
	}

	infof("running app")

	labels := map[string]string{
		// secondary_key doesn't seem to work correctly, might be a bug
		"custom.googleapis.com/secondary_key": versionName,
		"version": versionName,
	}

	// we need a goroutine to wait for the process to exit
	go func() {
		// create a goroutine for each pipe to read from the output until complete
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				log(logging.Info, appName, scanner.Text(), labels)
			}
			if err := scanner.Err(); err != nil {
				errorf("error reading from child process err=%v", err)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				log(logging.Error, appName, scanner.Text(), labels)
			}
			if err := scanner.Err(); err != nil {
				errorf("error reading from child process err=%v", err)
			}
		}()
		wg.Wait()
		ap.Command.Wait()
		infof("app exited version=%d", version)
		ap.Exited <- true
	}()

	return ap, nil
}

func main() {
	var err error
	project, err = metadata.ProjectID()
	V(err)
	appName, err = metadata.Get("instance/attributes/app")
	V(err)
	bucket, err := metadata.Get("instance/attributes/bucket")
	V(err)
	instance, err := metadata.InstanceName()
	V(err)

	client := &http.Client{
		Transport: &oauth2.Transport{
			Source: google.ComputeTokenSource(""),
		},
	}
	c := cloud.NewContext(project, client)

	// https://godoc.org/google.golang.org/cloud/logging
	// https://cloud.google.com/logging/docs/api/ref/rest/v1beta3/projects.logs.entries/write
	// https://github.com/google/google-api-go-client/blob/master/logging/v1beta3/logging-gen.go
	// https://cloud.google.com/logging/docs/view/logs_index
	// http://stackoverflow.com/questions/30698072/google-logging-api-what-service-name-to-use-when-writing-entries-from-non-goog
	logger, err = logging.NewClient(c, project, "engineer", cloud.WithTokenSource(google.ComputeTokenSource("")))
	V(err)
	logger.CommonLabels = map[string]string{
		// special keys for filtering in the cloud console log viewer
		"custom.googleapis.com/primary_key": appName,
		"app":      appName,
		"instance": instance,
	}

	if len(os.Args) != 2 {
		fatal("invalid args")
	}

	action := os.Args[1]
	switch action {
	case "run":
		shutdown := make(chan os.Signal, 1)
		signal.Notify(shutdown, syscall.SIGTERM)

		update := make(chan bool, 1)

		var statusMutex sync.Mutex
		var start time.Time
		var running bool
		var offline bool

		dir := filepath.Dir(socketPath)
		V(os.MkdirAll(dir, 0700))
		if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
			V(err)
		}
		listen, err := net.Listen("unix", socketPath)
		V(err)
		go func() {
			for {
				sock, err := listen.Accept()
				if err != nil {
					errorf("accept error=%v", err)
					continue
				}

				scanner := bufio.NewScanner(sock)
				for scanner.Scan() {
					command := scanner.Text()
					switch command {
					case "update":
						sock.Write([]byte("done\n"))
						select {
						case update <- true:
						default:
						}
					case "uptime":
						statusMutex.Lock()
						if running {
							sock.Write([]byte(fmt.Sprintf("%d\n", int(time.Now().Sub(start).Seconds()))))
						} else {
							sock.Write([]byte("0\n"))
						}
						statusMutex.Unlock()
					default:
						errorf("unrecognized command=%s", command)
					}
				}
				if err := scanner.Err(); err != nil {
					errorf("scanner error=%v", err)
				}
			}
		}()

		// serve this page for the health check
		go func() {
			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				statusMutex.Lock()
				if offline {
					w.WriteHeader(500)
					fmt.Fprintf(w, "Engineer is offline\n")
				} else if running {
					fmt.Fprintf(w, "Engineer is running\n")
				} else {
					w.WriteHeader(500)
					fmt.Fprintf(w, "Engineer is stopped\n")
				}
				statusMutex.Unlock()
			})

			if err := http.ListenAndServe(":8080", nil); err != nil {
				fatal(err)
			}
		}()

		// agent should not die accidentally within this loop unless something is really wrong
		for {
			contents, err := ioutil.ReadFile(localStatePath)
			V(err)
			state := engineer.State{}
			V(json.Unmarshal(contents, &state))

			if state.Version == 0 {
				select {
				case <-shutdown:
					exit(0)
				case <-update:
				}
				continue
			}

			ap, err := startVersion(state.Version)
			if err != nil {
				errorf("failed to start app err=%v", err)
				time.Sleep(5 * time.Second)
				select {
				case <-shutdown:
					infof("shutting down")
					exit(0)
				default:
				}
				continue
			}

			statusMutex.Lock()
			running = true
			start = time.Now()
			statusMutex.Unlock()
			select {
			case <-shutdown:
				// machine is shutting down, exit, killing the child app
				statusMutex.Lock()
				offline = true
				statusMutex.Unlock()
				infof("going offline")
				time.Sleep(30 * time.Second)
				ap.Command.Process.Signal(syscall.SIGTERM)
				infof("shutting down in 60 seconds")
				time.Sleep(60 * time.Second)
				infof("shutting down")
				exit(0)
			case <-update:
				infof("updating")

				if ap.GracefulShutdown {
					go func() {
						// give the new app 5 seconds to boot
						time.Sleep(5 * time.Second)
						// tell the old version to die now that we've hopefully launched the new version
						infof("telling old version to shutdown")
						ap.Command.Process.Signal(syscall.SIGTERM)
					}()
				} else {
					// kill app
					ap.Command.Process.Signal(syscall.SIGTERM)
					select {
					case <-ap.Exited:
					case <-time.After(5 * time.Second):
						ap.Command.Process.Kill()
					}
				}
			case <-ap.Exited:
				// app died, wait and then restart
				errorf("app died")
				statusMutex.Lock()
				running = false
				statusMutex.Unlock()
				time.Sleep(5 * time.Second)
			}
		}
	case "setup":
		WriteFile(
			"/etc/sysctl.conf",
			"fs.file-max = 1048576\n",
			0644,
		)
		Run("sysctl -w fs.file-max=1048576")
		if code := RunWithExit(fmt.Sprintf("groupadd -g %d app", appUID)); code != 0 && code != 9 {
			fatal("failed to create group")
		}
		if code := RunWithExit(fmt.Sprintf("useradd -r app -u %d -g %d", appUID, appUID)); code != 0 && code != 9 {
			fatal("failed to create user")
		}

		state, err := engineer.GetState(c, bucket)
		V(err)
		j, err := json.Marshal(state)
		V(err)
		fetchVersion(c, bucket, state.Version)
		V(ioutil.WriteFile(localStatePath, j, 0644))

		unitFile := `[Unit]
	Description=Engineer Agent

	[Service]
	ExecStart=/agent/agent run
	WorkingDirectory=/agent
	Restart=always
	RestartSec=30
	LimitNOFILE=1048576
	User=app
	KillMode=process
	TimeoutStopSec=95s

	[Install]
	WantedBy=multi-user.target
	`

		V(ioutil.WriteFile("/agent/agent.service", []byte(unitFile), 0644))
		Run("systemctl enable /agent/agent.service")
		Run("systemctl daemon-reload")
		Run("systemctl start agent.service")
	case "update":
		state, err := engineer.GetState(c, bucket)
		V(err)
		fetchVersion(c, bucket, state.Version)
		j, err := json.Marshal(state)
		V(err)
		V(ioutil.WriteFile(localStatePath, j, 0644))
		sendMessage("update")
	case "status":
		status := struct {
			InstanceUptime time.Duration
			AppUptime      time.Duration
			AppVersion     int
		}{}

		{
			contents, err := ioutil.ReadFile("/proc/uptime")
			V(err)

			parts := strings.Split(string(contents), " ")
			f, err := strconv.ParseFloat(parts[0], 64)
			V(err)
			status.InstanceUptime = time.Duration(f) * time.Second
		}

		{
			contents, err := ioutil.ReadFile(localStatePath)
			V(err)
			state := engineer.State{}
			V(json.Unmarshal(contents, &state))
			status.AppVersion = state.Version
		}

		{
			response := sendMessage("uptime")
			i, err := strconv.Atoi(response)
			V(err)
			status.AppUptime = time.Duration(i) * time.Second
		}

		j, err := json.Marshal(status)
		V(err)
		fmt.Println(string(j))
	default:
		fatal("invalid action=" + action)
	}

	exit(0)
}
