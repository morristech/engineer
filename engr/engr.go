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
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"github.com/pushbullet/engineer/internal"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	rawiam "google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"
	rawpubsub "google.golang.org/api/pubsub/v1"
	rawstorage "google.golang.org/api/storage/v1"
	fsnotify "gopkg.in/fsnotify.v1"
)

var ctx context.Context = context.Background()
var gcps *rawpubsub.Service
var gcs *rawstorage.Service
var gce *compute.Service
var iam *rawiam.Service
var crm *cloudresourcemanager.Service
var storageClient *storage.Client
var pubsubClient *pubsub.Client
var showLogPrefix = false

const (
	// http://ascii-table.com/ansi-escape-sequences.php
	Red    = "\x1b[31;1m"
	Green  = "\x1b[32;1m"
	Blue   = "\x1b[34;1m"
	Yellow = "\x1b[33;1m"
	Reset  = "\x1b[0m"
)

type Command struct {
	Name string
	Args []string

	App               internal.App
	AppBucketRequired bool
}

type Config struct {
	Apps map[string]internal.App `json:"apps"`
}

func infof(f string, args ...interface{}) {
	prefix := ""
	if showLogPrefix {
		prefix = "[engr] "
	}
	fmt.Printf(Blue+prefix+f+Reset+"\n", args...)
}

func warningf(f string, args ...interface{}) {
	prefix := ""
	if showLogPrefix {
		prefix = "[engr] "
	}
	fmt.Printf(Yellow+prefix+f+Reset+"\n", args...)
}

func errorf(f string, args ...interface{}) {
	prefix := ""
	if showLogPrefix {
		prefix = "[engr] "
	}
	fmt.Printf(Red+prefix+f+Reset+"\n", args...)
}

func exitf(f string, args ...interface{}) {
	errorf(f, args...)
	os.Exit(1)
}

func V(err error) {
	if err != nil {
		panic(err)
	}
}

func formatDuration(d time.Duration) string {
	if d.Hours() > 1 {
		return fmt.Sprintf("%.0fh", d.Hours())
	}
	if d.Minutes() > 1 {
		return fmt.Sprintf("%.0fm", d.Minutes())
	}
	return fmt.Sprintf("%.0fs", d.Seconds())
}

func findGOPATH() (string, error) {
	gopath := ""
	// get gopath from go tool
	output, err := exec.Command("go", "env").CombinedOutput()
	if err != nil {
		return "", err
	}
	for _, part := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(part, "GOPATH=") {
			gopath = part[8 : len(part)-1]
			break
		}
	}

	if gopath == "" {
		return "", errors.New("could not determine GOPATH")
	}
	return gopath, nil
}

func buildExecutable(app internal.App, local bool) (string, error) {
	// figure out gopath based on output from go env
	// we need gopath to figure out where the binaries will end up because we use go install
	// we use go install because it's much faster than go build
	gopath, err := findGOPATH()
	if err != nil {
		return "", err
	}

	pkg := app.Package
	if app.Generate {
		infof("running go generate")
		cmd := exec.Command("go", "generate", pkg)
		cmd.Env = []string{"GOPATH=" + gopath, "PATH=" + os.Getenv("PATH")}
		output, err := cmd.CombinedOutput()
		if err != nil {
			errorf("generate error=%v output=%s", err, output)
			return "", err
		}
	}

	infof("installing package=%s", pkg)

	cmd := exec.Command("go", "install", pkg)
	cmd.Env = []string{"GOPATH=" + gopath}
	outputPath := filepath.Join(gopath, "bin", filepath.Base(pkg))

	if !local {
		cmd.Env = append(cmd.Env, "GOOS=linux", "GOARCH=amd64")
		outputPath = filepath.Join(gopath, "bin", "linux_amd64", filepath.Base(pkg))
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		errorf("build error=%v output=%s", err, output)
		return "", err
	}
	return outputPath, nil
}

func runApp(app internal.App) chan bool {
	restart := make(chan bool)

	startApp := func() (*exec.Cmd, error) {
		path, err := buildExecutable(app, true)
		if err != nil {
			return nil, err
		}

		environment := []string{
			"ENGR_APP=" + app.Name,
			"ENGR_VERSION=0",
			"ENGR_PROJECT=" + app.Project,
			"ENGR_DEVELOPMENT=1",
		}

		if app.Local {
			environment = append(environment, os.Environ()...)
		} else {
			env := map[string]string{}
			state, err := getState(ctx, app.Bucket())
			if err != nil {
				return nil, err
			}
			if state.Version == 0 {
				exitf("no version deployed yet")
			}

			env, err = getEnv(app, state.Version)
			if err != nil {
				return nil, err
			}

			for k, v := range env {
				environment = append(environment, fmt.Sprintf("%s=%s", k, v))
			}
		}

		tmpDir, err := ioutil.TempDir("", "")
		if err != nil {
			return nil, err
		}

		cmd := &exec.Cmd{
			Path: path,
			Dir:  tmpDir,
			Env:  environment,
		}

		stdout, err := cmd.StdoutPipe()
		V(err)
		stderr, err := cmd.StderrPipe()
		V(err)

		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				fmt.Print(Green + "[" + app.Name + "] " + scanner.Text() + Reset + "\n")
			}
			if err := scanner.Err(); err != nil {
				errorf("error reading from child process err=%v", err)
			}
		}()
		go func() {
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				fmt.Print(Red + "[" + app.Name + "] ERROR: " + scanner.Text() + Reset + "\n")
			}
			if err := scanner.Err(); err != nil {
				errorf("error reading from child process err=%v", err)
			}
		}()

		infof("starting app name=%s", app.Name)
		if err := cmd.Start(); err != nil {
			return nil, err
		}

		return cmd, nil
	}

	go func() {
		for {
			cmd, err := startApp()
			if err == nil {
				go func() {
					select {
					case <-restart:
						cmd.Process.Kill()
					}
				}()

				if err := cmd.Wait(); err != nil && err.Error() != "signal: killed" {
					errorf("process exited abnormally: err=%v", err)
					time.Sleep(1 * time.Second)
				}
			} else {
				errorf("failed to start process err=%v", err)
				<-restart
			}
		}
	}()

	return restart
}

func serve(app internal.App) {
	showLogPrefix = true

	var (
		changedFiles     []string
		changedFilesLock sync.Mutex
	)

	var rLimit syscall.Rlimit
	rLimit.Max = 1048576
	rLimit.Cur = 1048576
	V(syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit))

	watcher, err := fsnotify.NewWatcher()
	V(err)

	visit := func(path string, f os.FileInfo, err error) error {
		if !f.IsDir() {
			return nil
		}

		if f.IsDir() {
			if strings.HasPrefix(f.Name(), ".") && f.Name() != "." {
				return filepath.SkipDir
			}
			if f.Name() == "pkg" {
				return filepath.SkipDir
			}
		}

		watcher.Add(path)
		return nil
	}

	exists := func(path string) bool {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return false
			}
			V(err)
		}
		return true
	}

	isDir := func(path string) bool {
		stat, err := os.Stat(path)
		if err != nil {
			V(err)
		}
		return stat.IsDir()
	}

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Chmod == fsnotify.Chmod {
					continue
				}
				changedFilesLock.Lock()
				changedFiles = append(changedFiles, event.Name)
				changedFilesLock.Unlock()
				if exists(event.Name) && isDir(event.Name) {
					V(filepath.Walk(event.Name, visit))
				}
			case err := <-watcher.Errors:
				log.Println("watch error:", err)
			}
		}
	}()

	V(filepath.Walk(".", visit))

	shouldRestart := false
	restartChan := runApp(app)

	for {
		changedFilesLock.Lock()
		lastChangedFiles := changedFiles
		changedFiles = []string{}
		changedFilesLock.Unlock()

		for _, path := range lastChangedFiles {
			infof("file changed path=%s", path)
			shouldRestart = true
			break
		}

		if shouldRestart {
			shouldRestart = false
			restartChan <- true
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type State struct {
	Version int
}

func getState(c context.Context, bucket string) (*State, error) {
	client, err := storage.NewClient(c)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	r, err := client.Bucket(bucket).Object("state.json").NewReader(c)
	if err != nil {
		return nil, err
	}
	state := &State{}
	if err := json.NewDecoder(r).Decode(state); err != nil {
		return nil, err
	}
	return state, nil
}

func putState(c context.Context, bucket string, state *State) error {
	client, err := storage.NewClient(c)
	if err != nil {
		return err
	}
	defer client.Close()
	w := client.Bucket(bucket).Object("state.json").NewWriter(c)
	if err := json.NewEncoder(w).Encode(state); err != nil {
		return err
	}
	return w.Close()
}

func getInstances(app internal.App, name string) []string {
	result, err := gce.InstanceGroupManagers.ListManagedInstances(app.Project, app.Zone, name).Do()
	V(err)
	instances := []string{}
	for _, instance := range result.ManagedInstances {
		instances = append(instances, lastComponent(instance.Instance, "/"))
	}
	return instances
}

func is404Error(err error) bool {
	if e, ok := err.(*googleapi.Error); ok {
		if e.Code == 404 {
			return true
		}
	}
	return false
}

func gcsWriter(app internal.App, name string) *storage.Writer {
	return storageClient.Bucket(app.Bucket()).Object(name).NewWriter(ctx)
}

func gcsVersionCopy(app internal.App, oldVersion int, newVersion int, name string) {
	srcName := strconv.Itoa(oldVersion) + "/" + name
	src := storageClient.Bucket(app.Bucket()).Object(srcName)
	dstName := strconv.Itoa(newVersion) + "/" + name
	dst := storageClient.Bucket(app.Bucket()).Object(dstName)
	start := time.Now()
	_, err := dst.CopierFrom(src).Run(ctx)
	V(err)
	infof("copied gcs file src=gs://%s/%s dst=gs://%s/%s in %.2fs", app.Bucket(), srcName, app.Bucket(), dstName, time.Now().Sub(start).Seconds())
}

func gcsWrite(app internal.App, name string, r io.Reader) {
	start := time.Now()
	w := gcsWriter(app, name)
	n, err := io.Copy(w, r)
	V(err)
	V(w.Close())
	infof("wrote gcs file path=gs://%s/%s %d bytes in %.2fs", app.Bucket(), name, n, time.Now().Sub(start).Seconds())
}

func gcsVersionWrite(app internal.App, version int, name string, r io.Reader) {
	gcsWrite(app, strconv.Itoa(version)+"/"+name, r)
}

func gcsVersionRead(app internal.App, version int, name string) []byte {
	r, err := storageClient.Bucket(app.Bucket()).Object(strconv.Itoa(version) + "/" + name).NewReader(ctx)
	V(err)
	contents, err := ioutil.ReadAll(r)
	V(err)
	return contents
}

func gcsDelete(app internal.App, name string) {
	infof("deleting gcs file path=gs://%s/%s", app.Bucket(), name)
	err := storageClient.Bucket(app.Bucket()).Object(name).Delete(ctx)
	if is404Error(err) {
		return
	}
	V(err)
}

func getEnv(app internal.App, version int) (map[string]string, error) {
	r, err := storageClient.Bucket(app.Bucket()).Object(strconv.Itoa(version) + "/env.json").NewReader(ctx)
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		return nil, err
	}
	return env, nil
}

func putEnv(app internal.App, version int, env map[string]string) {
	j, err := json.Marshal(env)
	V(err)
	gcsVersionWrite(app, version, "env.json", bytes.NewReader(j))
}

func lastComponent(u string, sep string) string {
	parts := strings.Split(u, sep)
	last := parts[len(parts)-1]
	if last == "" {
		return u
	} else {
		return last
	}
}

func exists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		}
		V(err)
	}
	return true
}

func readConfig() Config {
	config := Config{}
	contents, err := ioutil.ReadFile("engr.json")
	if err != nil {
		exitf("could not read engr.json")
	}

	if err := json.Unmarshal(contents, &config); err != nil {
		exitf("could not parse engr.json")
	}
	return config
}

func writeConfig(config Config) {
	contents, err := json.MarshalIndent(config, "", "  ")
	V(err)

	V(ioutil.WriteFile("engr.json", contents, 0644))
}

func runCommand(cmd Command) {
	app := cmd.App
	bucket := storageClient.Bucket(app.Bucket())
	_, err := bucket.Attrs(ctx)
	if err != nil && err != storage.ErrBucketNotExist {
		V(err)
	}
	bucketExists := err == nil

	if !app.StagedDeploy {
		switch cmd.Name {
		case "deploy", "env:set", "env:unset", "status", "rollback": //, "offline":
			// prepare an RPC subscription for these commands
			go PrepareRPC(ctx, app.Name, pubsubClient)
		}
	}

	if cmd.AppBucketRequired {
		if !bucketExists {
			exitf("missing app bucket name=%s", app.Bucket())
		}
	}

	switch cmd.Name {
	case "destroy-app":
		if !ask("destroy app "+app.Name+"?", false) {
			return
		}

		infof("destroying app=%s", app.Name)

		igms, err := gce.InstanceGroupManagers.List(app.Project, app.Zone).Filter(fmt.Sprintf(`name eq '%s-group.*'`, app.Name)).Do()
		V(err)
		for _, igm := range igms.Items {
			infof("destroying instance group name=%s", igm.Name)
			wait(gce.InstanceGroupManagers.Delete(app.Project, app.Zone, igm.Name).Do())
			infof("destroying instance group template name=%s", lastComponent(igm.InstanceTemplate, "/"))
			wait(gce.InstanceTemplates.Delete(app.Project, lastComponent(igm.InstanceTemplate, "/")).Do())
		}

		templates, err := gce.InstanceTemplates.List(app.Project).Filter(fmt.Sprintf(`name eq '%s-template.*'`, app.Name)).Do()
		V(err)
		for _, template := range templates.Items {
			infof("destroying instance group template name=%s", template.Name)
			wait(gce.InstanceTemplates.Delete(app.Project, template.Name).Do())
		}

		destroyGlobalResources(app)

		if resourceExists(iam.Projects.ServiceAccounts.Get(app.ServiceAccountName()).Do()) {
			infof("destroying service account name=%s", app.ServiceAccount())
			_, err := iam.Projects.ServiceAccounts.Delete(app.ServiceAccountName()).Do()
			V(err)
		}

		// delete all items then delete the bucket
		// (bucket cannot be deleted unless all items are deleted, at least with this delete call)
		if bucketExists && ask("destroy the bucket "+app.Bucket()+"?", false) {
			infof("destroying bucket name=%s", app.Bucket())
			var query *storage.Query
			iter := bucket.Objects(ctx, query)
			for {
				object, err := iter.Next()
				if err == iterator.Done {
					break
				}
				V(err)
				bucket.Object(object.Name).Delete(ctx)
			}
			V(gcs.Buckets.Delete(app.Bucket()).Do())
		}
	case "deploy":
		if cmd.App.Package == "" {
			exitf(`this app does not have a package set, try setting it with "engr config %s package <package>`, cmd.App.Name)
		}

		if !bucketExists {
			if !ask("this app has never been deployed before, create it?", true) {
				return
			}
			infof("creating environment name=%s project=%s", app.Name, app.Project)

			// https://cloud.google.com/compute/docs/access/service-accounts#service_account_permissions
			if !resourceExists(iam.Projects.ServiceAccounts.Get(app.ServiceAccountName()).Do()) {
				infof("creating service account name=%s", app.ServiceAccount())
				_, err := iam.Projects.ServiceAccounts.Create("projects/"+app.Project, &rawiam.CreateServiceAccountRequest{AccountId: app.ServiceAccount(), ServiceAccount: &rawiam.ServiceAccount{DisplayName: app.ServiceAccount()}}).Do()
				V(err)
			}

			infof("creating bucket name=%s", app.Bucket())
			_, err := gcs.Buckets.Insert(app.Project, &rawstorage.Bucket{Name: app.Bucket()}).Do()
			V(err)
			gcsWrite(app, "state.json", strings.NewReader("{}"))

			_, err = gcs.BucketAccessControls.Insert(app.Bucket(), &rawstorage.BucketAccessControl{Entity: "user-" + app.ServiceAccountEmail(), Role: "READER"}).Do()
			V(err)

			_, err = gcs.DefaultObjectAccessControls.Insert(app.Bucket(), &rawstorage.ObjectAccessControl{Entity: "user-" + app.ServiceAccountEmail(), Role: "READER"}).Do()
			V(err)
		}

		infof("getting state")
		state, err := getState(ctx, app.Bucket())
		V(err)
		state.Version++

		if state.Version == 1 {
			createGlobalResources(app)
		}

		path, err := buildExecutable(app, false)
		V(err)

		infof("uploading files")
		buf := &bytes.Buffer{}
		zw := zip.NewWriter(buf)
		{
			fw, err := zw.Create(filepath.Base(app.Package))
			V(err)
			r, err := os.Open(path)
			V(err)
			_, err = io.Copy(fw, r)
			V(err)
		}

		V(zw.Close())
		gcsVersionWrite(app, state.Version, "package.zip", buf)

		if state.Version == 1 {
			gcsVersionWrite(app, state.Version, "env.json", strings.NewReader("{}"))
		} else {
			gcsVersionCopy(app, state.Version-1, state.Version, "env.json")
		}

		{
			j, err := json.Marshal(app)
			V(err)
			gcsVersionWrite(app, state.Version, "app.json", bytes.NewReader(j))
		}

		infof("updating state")
		V(putState(ctx, app.Bucket(), state))

		updateRoles(app)
		deployApp(app, state.Version)

		infof("deployed version=%d", state.Version)
	case "serve":
		serve(app)
	case "logs":
		V(exec.Command("open", fmt.Sprintf("https://console.developers.google.com/logs?project=%s&service=custom.googleapis.com&key1=%s", app.Project, app.Name)).Run())
	case "status":
		infof("app=%s", app.Name)
		state, err := getState(ctx, app.Bucket())
		V(err)
		infof("version=%d", state.Version)

		if app.Server {
			forwardingRule, err := gce.ForwardingRules.Get(app.Project, app.Region(), app.ForwardingRule()).Do()
			V(err)
			infof("ip=%s", forwardingRule.IPAddress)
		}

		resp, err := gce.InstanceGroupManagers.List(app.Project, app.Zone).Filter(fmt.Sprintf(`name eq '%s-group.*'`, app.Name)).Do()
		V(err)
		for _, igm := range resp.Items {
			infof("\n\ninstance-group=%s", igm.Name)

			parts := strings.Split(igm.InstanceTemplate, "-")
			versionRaw := parts[len(parts)-1]
			version, err := strconv.Atoi(versionRaw)
			V(err)

			infof("template-version=%d", version)

			instanceTemplate, err := gce.InstanceTemplates.Get(app.Project, lastComponent(igm.InstanceTemplate, "/")).Do()
			V(err)
			infof("instance-type=%s", instanceTemplate.Properties.MachineType)

			infof("target-size=%d", igm.TargetSize)

			result, err := gce.InstanceGroupManagers.ListManagedInstances(app.Project, app.Zone, igm.Name).Do()
			V(err)
			infof("instance-count=%d", len(result.ManagedInstances))

			infof("scopes=%s", strings.Join(instanceTemplate.Properties.ServiceAccounts[0].Scopes, " "))
			tags := []string{}
			if instanceTemplate.Properties.Tags != nil {
				tags = instanceTemplate.Properties.Tags.Items
			}
			infof("tags=%s", strings.Join(tags, " "))

			infof("\ninstance status")
			tc, _ := context.WithTimeout(ctx, 15*time.Second)
			msgs, err := RPC(tc, app.Name, internal.CommandStatus, 0, len(getInstances(app, igm.Name)), pubsubClient)
			if err != context.DeadlineExceeded {
				V(err)
			}
			instanceStatus := map[string]internal.StatusResult{}
			for _, msg := range msgs {
				instanceStatus[msg.Instance] = msg.StatusResult
			}

			for _, instance := range result.ManagedInstances {
				instanceName := lastComponent(instance.Instance, "/")
				result, err := gce.Instances.Get(app.Project, app.Zone, instanceName).Do()
				if is404Error(err) {
					continue
				}
				V(err)
				infof(instanceName+"[status]=%s", result.Status)

				if app.Server {
					health, err := gce.TargetPools.GetHealth(app.Project, app.Region(), app.TargetPool(), &compute.InstanceReference{Instance: instance.Instance}).Do()
					if err == nil && len(health.HealthStatus) > 0 {
						infof(instanceName+"[health]=%+v", health.HealthStatus[0].HealthState)
					} else {
						infof(instanceName + "[health]=UNKNOWN")
					}
				}

				created, err := time.Parse(time.RFC3339, result.CreationTimestamp)
				V(err)
				infof(instanceName+"[instance-age]=%s", formatDuration(time.Now().Sub(created)))

				status, ok := instanceStatus[instanceName]
				if ok {
					infof(instanceName+"[instance-uptime]=%s", formatDuration(status.InstanceUptime))
					infof(instanceName+"[app-uptime]=%s", formatDuration(status.AppUptime))
					infof(instanceName+"[app-version]=%d", status.AppVersion)
				} else {
					infof(instanceName + "[instance-uptime]=UNKNOWN")
					infof(instanceName + "[app-uptime]=UNKNOWN")
					infof(instanceName + "[app-version]=UNKNOWN")
				}
			}
		}
	case "env", "env:get", "env:set", "env:unset":
		state, err := getState(ctx, app.Bucket())
		V(err)
		if state.Version == 0 {
			exitf("no version deployed yet")
		}

		env, err := getEnv(app, state.Version)
		V(err)

		switch cmd.Name {
		case "env":
			for k, v := range env {
				infof("%s=%s", k, v)
			}
		case "env:get":
			if len(cmd.Args) != 1 {
				exitf("you must specify a key")
			}
			k := cmd.Args[0]
			infof("%s=%s", k, env[k])
		case "env:set", "env:unset":
			if len(cmd.Args) == 0 {
				exitf("you must specify a key")
			}

			if cmd.Name == "env:set" {
				for i := 0; i < len(cmd.Args); i += 2 {
					key := cmd.Args[i]
					value := cmd.Args[i+1]
					if strings.HasPrefix(value, "@") {
						// load from file
						contents, err := ioutil.ReadFile(value[1:])
						V(err)
						value = string(contents)
					}
					env[key] = value
					infof("%s=%s", key, value)
				}
			} else {
				for _, key := range cmd.Args {
					delete(env, key)
					infof("%s=<unset>", key)
				}
			}

			infof("updating state")
			state.Version++
			gcsVersionCopy(app, state.Version-1, state.Version, "package.zip")
			gcsVersionCopy(app, state.Version-1, state.Version, "app.json")
			putEnv(app, state.Version, env)
			V(putState(ctx, app.Bucket(), state))

			deployApp(app, state.Version)
			infof("deployed version=%d", state.Version)
		default:
			exitf("unrecognized command")
		}
	case "rollback":
		version, err := strconv.Atoi(cmd.Args[0])
		if err != nil {
			exitf("version must be a number")
		}
		state, err := getState(ctx, app.Bucket())
		V(err)
		if state.Version == version {
			exitf("can't rollback to the current version")
		}
		if version > state.Version {
			exitf("not a valid version")
		}

		infof("rolling back to version=%d", version)
		infof("updating state")
		state.Version++
		gcsVersionCopy(app, version, state.Version, "package.zip")
		gcsVersionCopy(app, version, state.Version, "app.json")
		gcsVersionCopy(app, version, state.Version, "env.json")
		V(putState(ctx, app.Bucket(), state))

		// get the old version of the app from GCS
		originalApp := app
		appJson := gcsVersionRead(originalApp, version, "app.json")
		app = internal.App{}
		V(json.Unmarshal(appJson, &app))
		app.Name = originalApp.Name

		deployApp(app, state.Version)
		infof("deployed version=%d", state.Version)
	case "run":
		state, err := getState(ctx, app.Bucket())
		V(err)
		if state.Version == 0 {
			exitf("no version deployed yet")
		}

		env, err := getEnv(app, state.Version)
		V(err)

		environment := []string{
			"GOPATH=" + os.Getenv("GOPATH"),
			"GOOGLE_APPLICATION_CREDENTIALS=" + os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"),
			"ENGR_PROJECT=" + app.Project,
			"ENGR_APP=" + app.Name,
			"ENGR_VERSION=" + strconv.Itoa(state.Version),
		}

		for k, v := range env {
			environment = append(environment, fmt.Sprintf("%s=%s", k, v))
		}

		path, err := exec.LookPath(cmd.Args[0])
		V(err)
		V(syscall.Exec(path, cmd.Args, environment))
	case "destroy":
		version, err := strconv.Atoi(cmd.Args[0])
		V(err)
		destroyInstanceGroup(app, app.InstanceGroup(version))
	// case "offline":
	// 	version, err := strconv.Atoi(cmd.Args[0])
	// 	V(err)
	// 	offlineInstanceGroup(app, app.InstanceGroup(version))
	default:
		exitf("invalid command=%s", cmd.Name)
	}
}

func main() {
	args := os.Args[1:]

	if len(args) < 2 {
		fmt.Printf(`Usage: engr <app> <command>

Command must be one of:

	serve
	deploy
	destroy
	create
	local-serve
	config
	config:get
	config:set
	config:unset
	rollback
	status
	env
	env:get
	env:set (@filename)
	env:unset
	destroy-app
	run
	logs
	debug
`)
		os.Exit(1)
		return
	}

	appName := args[0]
	command := args[1]

	if command == "create" {
		if !exists("engr.json") {
			if err := ioutil.WriteFile("engr.json", []byte("{}"), 0644); err != nil {
				exitf("could not create engr.json")
			}
		}

		config := readConfig()

		if config.Apps == nil {
			config.Apps = map[string]internal.App{}
		}

		if _, ok := config.Apps[appName]; !ok {
			infof("creating app=%s", appName)
			infof(`set a project for your app with "engr %s config:set project <project>"`, appName)
			infof(`deploy the app with "engr %s deploy"`, appName)
			config.Apps[appName] = internal.App{
				Package:       "github.com/pushbullet/engineer/examples/environ",
				Server:        true,
				Roles:         []string{},
				Tags:          []string{"http-server"},
				Zone:          "us-central1-c",
				InstanceCount: 1,
				MachineType:   "f1-micro",
			}
		}

		writeConfig(config)
		return
	}

	config := Config{}
	{
		if !exists("engr.json") {
			exitf(`could not find engr.json, please run "engr <app> create" to create it`)
		}

		config = readConfig()
	}

	app, ok := config.Apps[appName]
	if !ok && command != "destroy-app" && command != "create" {
		exitf("invalid app name=%s", appName)
	}
	app.Name = appName

	if command == "debug" {
		V(exec.Command("open", "https://console.cloud.google.com/debug?project="+app.Project).Run())
		return
	}

	if command == "logs" {
		url := fmt.Sprintf("https://console.developers.google.com/logs?project=%s&service=custom.googleapis.com&key1=%s", app.Project, app.Name)
		V(exec.Command("open", url).Run())
		return
	}

	if strings.HasPrefix(command, "config") {
		config := readConfig()

		printKey := func(key string) {
			switch key {
			case "package":
				infof("package=%s", app.Package)
			case "server":
				infof("server=%v", app.Server)
			case "debug":
				infof("debug=%v", app.Debug)
			case "graceful-shutdown":
				infof("graceful-shutdown=%v", app.GracefulShutdown)
			case "roles":
				infof("roles=%s", strings.Join(app.Roles, " "))
			case "tags":
				infof("tags=%s", strings.Join(app.Tags, " "))
			case "instance-count":
				infof("instance-count=%d", app.InstanceCount)
			case "machine-type":
				infof("machine-type=%s", app.MachineType)
			case "project":
				infof("project=%s", app.Project)
			case "zone":
				infof("zone=%s", app.Zone)
			case "image":
				infof("image=%s", app.Image)
			case "staged-deploy":
				infof("staged-deploy=%v", app.StagedDeploy)
			case "generate":
				infof("generate=%v", app.Generate)
			default:
				exitf("unrecognized configuration option name=%s", args[2])
			}
		}

		switch command {
		case "config":
			infof("package=%s", app.Package)
			infof("server=%v", app.Server)
			infof("debug=%v", app.Debug)
			infof("graceful-shutdown=%v", app.GracefulShutdown)
			infof("roles=%s", strings.Join(app.Roles, " "))
			infof("tags=%s", strings.Join(app.Tags, " "))
			infof("instance-count=%d", app.InstanceCount)
			infof("machine-type=%s", app.MachineType)
			infof("project=%s", app.Project)
			infof("zone=%s", app.Zone)
			infof("image=%s", app.Image)
			infof("staged-deploy=%v", app.StagedDeploy)
			infof("generate=%v", app.Generate)
		case "config:get":
			if len(args) != 3 {
				exitf("you must specify a key")
			}
			printKey(args[2])
		case "config:set", "config:unset":
			key := args[2]
			values := args[3:]

			if command == "config:unset" {
				values = []string{""}
			}

			switch key {
			case "package":
				app.Package = values[0]
			case "server":
				app.Server = values[0] == "true"
			case "debug":
				app.Debug = values[0] == "true"
			case "graceful-shutdown":
				app.GracefulShutdown = values[0] == "true"
			case "roles":
				roles := []string{}
				for _, v := range values {
					if v != "" {
						roles = append(roles, v)
					}
				}
				app.Roles = roles
			case "tags":
				tags := []string{}
				for _, v := range values {
					if v != "" {
						tags = append(tags, v)
					}
				}
				app.Tags = tags
			case "instance-count":
				i, err := strconv.Atoi(values[0])
				if err != nil {
					exitf("invalid number=%s", values[0])
				}
				app.InstanceCount = i
			case "machine-type":
				app.MachineType = values[0]
			case "project":
				app.Project = values[0]
			case "zone":
				app.Zone = values[0]
			case "image":
				app.Image = values[0]
			case "staged-deploy":
				app.StagedDeploy = values[0] == "true"
			case "generate":
				app.Generate = values[0] == "true"
			default:
				exitf("unrecognized configuration option name=%s", key)
			}
			config.Apps[appName] = app
			writeConfig(config)
			printKey(key)
		}

		return
	}

	cmd := Command{
		Name:              command,
		Args:              args[2:],
		AppBucketRequired: true,
	}

	switch cmd.Name {
	case "destroy-app", "deploy", "logs":
		cmd.AppBucketRequired = false
	}

	cmd.App = app

	if command == "local-serve" {
		cmd.App.Local = true
		serve(cmd.App)
		return
	}

	{
		if cmd.App.Project == "" {
			exitf(`this app does not have a project set, try setting it with "engr %s config:set project <project>`, cmd.App.Name)
		}

		client, err := google.DefaultClient(oauth2.NoContext, "https://www.googleapis.com/auth/devstorage.read_write", "https://www.googleapis.com/auth/compute", "https://www.googleapis.com/auth/pubsub")
		if err != nil {
			exitf("could not find google account, make sure you have run `gcloud auth login`\nerr=%v", err)
		}
		gce, err = compute.New(client)
		V(err)
		gcs, err = rawstorage.New(client)
		V(err)
		gcps, err = rawpubsub.New(client)
		V(err)
		iam, err = rawiam.New(client)
		V(err)
		crm, err = cloudresourcemanager.New(client)
		V(err)

		// do a test request to see if our token is good
		if _, err := gcs.Buckets.List(cmd.App.Project).Do(); err != nil {
			exitf("google account does not seem to work, try running `gcloud auth login`\nerr=%v", err)
		}

		storageClient, err = storage.NewClient(ctx)
		V(err)

		pubsubClient, err = pubsub.NewClient(ctx, cmd.App.Project)
		V(err)
	}

	start := time.Now()
	runCommand(cmd)
	infof("elapsed: %.1fs", time.Now().Sub(start).Seconds())
}
