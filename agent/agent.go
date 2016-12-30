package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
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

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/logging"
	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"github.com/pushbullet/engineer/internal"
	"golang.org/x/net/context"
	"google.golang.org/grpc/grpclog"
)

const (
	localVersionPath = "/agent/version"
	appUID           = 2000
)

var (
	logger       *logging.Logger
	pubsubClient *pubsub.Client
	appName      string
	project      string
)

func _log(severity logging.Severity, prefix string, message string, labels map[string]string) {
	if strings.HasPrefix(message, "http: TLS handshake error from ") {
		// there's a bunch of these caused by HTTPS port scanners, so just discard these in production
		// https://groups.google.com/forum/#!topic/golang-nuts/d4sjZR7H4gU
		return
	}

	if strings.Contains(message, "transport: http2Client.notifyError got notified that the client transport was broken EOF.") {
		// this happens every 4 minutes due to inactivity, the log message appears pointless
		// https://github.com/GoogleCloudPlatform/google-cloud-go/issues/293
		return
	}

	if logger == nil {
		printMessage := message
		if severity == logging.Error {
			printMessage = "ERROR: " + message
		}
		fmt.Println("[" + prefix + "] " + printMessage)
		return
	}

	hostname, _ := os.Hostname()

	logger.Log(logging.Entry{
		Severity: severity,
		Payload:  fmt.Sprintf("%s[%s]: %s", prefix, hostname, message),
		Labels:   labels,
	})
}

func infof(f string, args ...interface{}) {
	_log(logging.Info, "agent", fmt.Sprintf(f, args...), nil)
}

func errorf(f string, args ...interface{}) {
	_log(logging.Error, "agent", fmt.Sprintf(f, args...), nil)
}

func fatal(v interface{}) {
	errorf("%+v", v)
	exit(1)
}

func exit(code int) {
	if logger != nil {
		logger.Flush()
	}
	os.Exit(code)
}

type LogConverter struct {
	logger *logging.Logger
}

func (lc *LogConverter) Fatal(args ...interface{}) {
	_log(logging.Error, "agent", fmt.Sprint(args...), nil)
	exit(1)
}

func (lc *LogConverter) Fatalf(format string, args ...interface{}) {
	_log(logging.Error, "agent", fmt.Sprintf(format, args...), nil)
	exit(1)
}

func (lc *LogConverter) Fatalln(args ...interface{}) {
	_log(logging.Error, "agent", fmt.Sprintln(args...), nil)
	exit(1)
}

func (lc *LogConverter) Print(args ...interface{}) {
	_log(logging.Info, "agent", fmt.Sprint(args...), nil)
}

func (lc *LogConverter) Printf(format string, args ...interface{}) {
	_log(logging.Info, "agent", fmt.Sprintf(format, args...), nil)
}

func (lc *LogConverter) Println(args ...interface{}) {
	_log(logging.Info, "agent", fmt.Sprintln(args...), nil)
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

func fetchVersion(c context.Context, bucketName string, version int) error {
	infof("fetching version %d", version)
	versionName := strconv.Itoa(version)
	dir := versionDir(version)
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		return err
	}

	client, err := storage.NewClient(c)
	if err != nil {
		return err
	}
	bucket := client.Bucket(bucketName)

	if !Exists(dir) {
		infof("extracting package")
		r, err := bucket.Object(versionName + "/package.zip").NewReader(c)
		if err != nil {
			return err
		}
		contents, err := ioutil.ReadAll(r)
		if err != nil {
			return err
		}
		z, err := zip.NewReader(bytes.NewReader(contents), int64(len(contents)))
		if err != nil {
			return err
		}

		for _, f := range z.File {
			input, err := f.Open()
			if err != nil {
				return err
			}
			output, err := os.OpenFile(tmpDir+"/"+f.Name, os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}
			_, err = io.Copy(output, input)
			if err != nil {
				return err
			}
			input.Close()
			output.Close()
		}

		if err := os.Rename(tmpDir, dir); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0755); err != nil {
			return err
		}
	}

	for _, filename := range []string{"app.json", "env.json"} {
		r, err := bucket.Object(versionName + "/" + filename).NewReader(c)
		if err != nil {
			return err
		}
		contents, err := ioutil.ReadAll(r)
		if err != nil {
			return err
		}
		path := filepath.Join(dir, filename)
		if err := ioutil.WriteFile(path, contents, 0644); err != nil {
			return err
		}
	}

	appJson, err := ioutil.ReadFile(dir + "/app.json")
	if err != nil {
		return err
	}
	app := internal.App{}
	if err := json.Unmarshal(appJson, &app); err != nil {
		return err
	}

	exePath := filepath.Join(dir, filepath.Base(app.Package))
	if err := os.Chmod(exePath, 0755); err != nil {
		return err
	}

	// let executable bind lower ports as non-root user
	if err := exec.Command("setcap", "cap_net_bind_service=+ep", exePath).Run(); err != nil {
		return err
	}

	return nil
}

func runCloudDebugger(app internal.App, version int) ([]string, error) {
	resp, err := http.Get("https://storage.googleapis.com/cloud-debugger/compute-go/cd_go_agent.sh")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	debuggerScript, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	dir := versionDir(version)
	cmd := exec.Command("/bin/bash", "-e", "-s", "--", "--program="+filepath.Join(dir, filepath.Base(app.Package)), "--module="+appName, "--version="+strconv.Itoa(version))
	cmd.Stdin = bytes.NewReader(debuggerScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("cloud debugger failed err=%v output=%s", err, output)
	}

	return strings.Split(strings.TrimSpace(string(output)), " "), nil
}

type AppProcess struct {
	Command          *exec.Cmd
	GracefulShutdown bool
	Exited           chan bool
}

func startVersion(version int) (*AppProcess, error) {
	dir := versionDir(version)

	appJson, err := ioutil.ReadFile(dir + "/app.json")
	if err != nil {
		return nil, err
	}

	app := internal.App{}
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

	cmd := exec.Command(filepath.Join(dir, filepath.Base(app.Package)))
	if app.Debug {
		args, err := runCloudDebugger(app, version)
		if err != nil {
			return nil, errors.New("failed to run cloud debugger")
		}
		infof("running cloud debugger")
		cmd = exec.Command(args[0], args[1:]...)
	}

	cmd.Dir = "/tmp"
	cmd.Env = environment

	if !app.Debug {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: appUID, Gid: appUID},
			// Pdeathsig should be set so that if the agent dies, it can restart the child process
			// without it, the child process will still be running and no longer monitored by the agent
			// Pdeathsig: syscall.SIGKILL,
			// this doesn't work since we use setcap on the executable
		}
	}

	ap := &AppProcess{
		Command:          cmd,
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

	// we need a goroutine to wait for the process to exit
	go func() {
		// create a goroutine for each pipe to read from the output until complete
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				_log(logging.Info, appName, scanner.Text(), nil)
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
				level := logging.Error
				if app.Debug {
					// the debugger takes stdout from the child process and reroutes it to stderr
					level = logging.Info
				}
				_log(level, appName, scanner.Text(), nil)
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

func updateCall(c context.Context, bucket string, version int) error {
	if err := fetchVersion(c, bucket, version); err != nil {
		return err
	}
	if err := ioutil.WriteFile(localVersionPath, []byte(strconv.Itoa(version)), 0644); err != nil {
		return err
	}
	return nil
}

func statusCall() (internal.StatusResult, error) {
	sr := internal.StatusResult{}
	{
		contents, err := ioutil.ReadFile("/proc/uptime")
		if err != nil {
			return sr, err
		}

		parts := strings.Split(string(contents), " ")
		f, err := strconv.ParseFloat(parts[0], 64)
		if err != nil {
			return sr, err
		}
		sr.InstanceUptime = time.Duration(f) * time.Second
	}

	sr.AppVersion = getAppVersion()
	return sr, nil
}

func getAppVersion() int {
	if Exists(localVersionPath) {
		contents, err := ioutil.ReadFile(localVersionPath)
		V(err)
		version, err := strconv.Atoi(string(contents))
		V(err)
		return version
	} else {
		versionRaw, err := metadata.Get("instance/attributes/app-version")
		V(err)
		version, err := strconv.Atoi(versionRaw)
		V(err)
		return version
	}
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

	c := context.Background()

	loggingClient, err := logging.NewClient(c, project)
	V(err)

	logger = loggingClient.Logger("engineer")

	// convert grpc logs to cloud logs
	grpclog.SetLogger(&LogConverter{logger})

	pubsubClient, err = pubsub.NewClient(c, project)
	V(err)

	if len(os.Args) != 2 {
		fatal("invalid args")
	}

	action := os.Args[1]
	switch action {
	case "run":
		// kill any running copies of app since Pdeathsig doesn't work
		exec.Command("pkill", "-9", "-u", strconv.Itoa(appUID)).Run()

		shutdown := make(chan os.Signal, 1)
		signal.Notify(shutdown, syscall.SIGTERM)

		update := make(chan bool, 1)

		var statusMutex sync.Mutex
		var start time.Time
		var running bool
		var offline bool

		processMessages := func() error {
			topic := internal.TopicFromAppName(pubsubClient, appName)
			sub := pubsubClient.Subscription(instance)

			exists, err := sub.Exists(c)
			if err != nil {
				return err
			}

			if !exists {
				if _, err := pubsubClient.CreateSubscription(c, sub.ID(), topic, 10*time.Second, nil); err != nil {
					return err
				}
			}

			it, err := sub.Pull(c)
			if err != nil {
				return err
			}
			defer it.Stop()

			for {
				msg, err := it.Next()
				if err != nil {
					return err
				}

				msg.Done(true)

				m := internal.Message{}
				if err := json.Unmarshal(msg.Data, &m); err != nil {
					return err
				}

				if m.Published.Add(60 * time.Second).Before(time.Now()) {
					infof("dropping expired message")
					continue
				}

				reply := func(c context.Context, resp internal.Message) {
					resp.RequestID = m.RequestID
					resp.Instance = instance
					if err := internal.SendMessage(c, resp, topic); err != nil {
						errorf("message send error=%v", err)
					}
				}

				switch m.Command {
				case internal.CommandUpdate:
					if m.UpdateVersion == getAppVersion() {
						reply(c, internal.Message{})
						infof("already running requested version")
						continue
					}
					if err := updateCall(c, bucket, m.UpdateVersion); err != nil {
						reply(c, internal.Message{Error: err.Error()})
						continue
					}
					reply(c, internal.Message{})

					select {
					case update <- true:
					default:
					}
				case internal.CommandStatus:
					sr, err := statusCall()
					if err != nil {
						reply(c, internal.Message{Error: err.Error()})
						continue
					}
					statusMutex.Lock()
					if running {
						sr.AppUptime = time.Now().Sub(start)
					}
					statusMutex.Unlock()
					reply(c, internal.Message{StatusResult: sr})
				default:
					// replies will show up here, since we use just a single topic
				}
			}
		}

		go func() {
			for {
				errorf("process messages error=%v", processMessages())
				time.Sleep(1 * time.Minute)
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
			appVersion := getAppVersion()

			if appVersion == 0 {
				select {
				case <-shutdown:
					exit(0)
				case <-update:
				}
				continue
			}

			ap, err := startVersion(appVersion)
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
				// machine is shutting down SIGTERM the child process and then exit
				statusMutex.Lock()
				offline = true
				statusMutex.Unlock()
				infof("going offline")
				time.Sleep(30 * time.Second)
				ap.Command.Process.Signal(syscall.SIGTERM)
				infof("shutting down in 60 seconds")
				time.Sleep(60 * time.Second)
				infof("shutting down")
				pubsubClient.Topic(instance).Delete(c)
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
				time.Sleep(30 * time.Second)
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

		V(fetchVersion(c, bucket, getAppVersion()))

		unitFile := `[Unit]
Description=Engineer Agent

[Service]
ExecStart=/agent/agent run
WorkingDirectory=/agent
Restart=always
RestartSec=30
LimitNOFILE=1048576
KillMode=process
TimeoutStopSec=95s

[Install]
WantedBy=multi-user.target
`

		V(ioutil.WriteFile("/agent/agent.service", []byte(unitFile), 0644))
		Run("systemctl enable /agent/agent.service")
		Run("systemctl daemon-reload")
		Run("systemctl start agent.service")
	default:
		fatal("invalid action=" + action)
	}

	exit(0)
}
