package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/fsnotify.v1"

	"github.com/pushbullet/engineer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	rawstorage "google.golang.org/api/storage/v1"
	"google.golang.org/cloud"
	"google.golang.org/cloud/storage"
)

const (
	agentVersion = 11
)

var sshKeyPath string
var inst Install
var ctx context.Context
var gcs *rawstorage.Service
var gce *compute.Service
var storageClient *storage.Client
var showLogPrefix = false

const (
	// http://ascii-table.com/ansi-escape-sequences.php
	Red    = "\x1b[31;1m"
	Green  = "\x1b[32;1m"
	Blue   = "\x1b[34;1m"
	Yellow = "\x1b[33;1m"
	Reset  = "\x1b[0m"
)

type Config struct {
	Deployments map[string]engineer.Deployment
	Apps        map[string]engineer.App
}

type Install struct {
	App        engineer.App
	Deployment engineer.Deployment
}

func (i *Install) TargetPool() string {
	return fmt.Sprintf("%s-%s-pool", i.Deployment.Name, i.App.Name)
}

func (i *Install) Address() string {
	return fmt.Sprintf("%s-%s-address", i.Deployment.Name, i.App.Name)
}

func (i *Install) ForwardingRule() string {
	return fmt.Sprintf("%s-%s-rule", i.Deployment.Name, i.App.Name)
}

func (i *Install) HealthCheck() string {
	return fmt.Sprintf("%s-%s-check", i.Deployment.Name, i.App.Name)
}

func (i *Install) InstanceGroup() string {
	return fmt.Sprintf("%s-%s-group", i.Deployment.Name, i.App.Name)
}

func (i *Install) TemplateBase() string {
	return fmt.Sprintf("%s-%s-template", i.Deployment.Name, i.App.Name)
}

func (i *Install) InstanceBase() string {
	return fmt.Sprintf("%s-%s", i.Deployment.Name, i.App.Name)
}

func (i *Install) Bucket() string {
	return fmt.Sprintf("%s-%s-%s", i.Deployment.Project, i.Deployment.Name, i.App.Name)
}

func (i *Install) DeploymentConfig() engineer.DeploymentConfig {
	dc := i.App.DeploymentConfig[i.Deployment.Name]
	if dc.MachineType == "" {
		dc.MachineType = "f1-micro"
	}
	if dc.InstanceCount == 0 {
		dc.InstanceCount = 1
	}
	return dc
}

func RegionFromZone(zone string) string {
	parts := strings.Split(zone, "-")
	return strings.Join(parts[:len(parts)-1], "-")
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
		exitf(err.Error())
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

func buildExecutable(pkg string, local bool) (string, error) {
	infof("building executable pkg=%s", pkg)
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		return "", err
	}
	outputPath := filepath.Join(tmpDir, filepath.Base(pkg))
	cmd := exec.Command("go", "build", "-i", "-o", outputPath, pkg)
	cmd.Env = os.Environ()
	if !local {
		cmd.Env = append(cmd.Env, "GOOS=linux", "GOARCH=amd64")
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		errorf("build error=%v output=%s", err, output)
		return "", err
	}
	return outputPath, nil
}

func runApp() chan bool {
	restart := make(chan bool)

	startApp := func() (*exec.Cmd, error) {
		path, err := buildExecutable(inst.App.Executable, true)
		if err != nil {
			return nil, err
		}

		environment := []string{
			"ENGR_APP=" + inst.App.Name,
			"ENGR_VERSION=0",
			"ENGR_PROJECT=" + inst.Deployment.Project,
			"ENGR_DEVELOPMENT=1",
			"GOOGLE_APPLICATION_CREDENTIALS=" + os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"),
		}

		env := map[string]string{}
		state, err := engineer.GetState(ctx, inst.Bucket())
		if err != nil {
			return nil, err
		}
		if state.Version == 0 {
			exitf("no version deployed yet")
		}

		env, err = getEnv(state.Version)
		if err != nil {
			return nil, err
		}

		for k, v := range env {
			environment = append(environment, fmt.Sprintf("%s=%s", k, v))
		}

		cmd := &exec.Cmd{
			Path: path,
			Env:  environment,
		}

		stdout, err := cmd.StdoutPipe()
		V(err)
		stderr, err := cmd.StderrPipe()
		V(err)

		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				fmt.Printf(Green + "[" + inst.App.Name + "] " + scanner.Text() + Reset + "\n")
			}
			if err := scanner.Err(); err != nil {
				errorf("error reading from child process err=%v", err)
			}
		}()
		go func() {
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				fmt.Printf(Red + "[" + inst.App.Name + "] ERROR: " + scanner.Text() + Reset + "\n")
			}
			if err := scanner.Err(); err != nil {
				errorf("error reading from child process err=%v", err)
			}
		}()

		infof("starting app name=%s", inst.App.Name)
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
				}
			} else {
				errorf("failed to start process err=%v", err)
				<-restart
			}
		}
	}()

	return restart
}

func serve() {
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

	ignorePaths := map[string]bool{"tags": true}
	shouldRestart := false
	restartChan := runApp()

	for {
		changedFilesLock.Lock()
		lastChangedFiles := changedFiles
		changedFiles = []string{}
		changedFilesLock.Unlock()

		for _, path := range lastChangedFiles {
			if !ignorePaths[path] {
				infof("file changed path=%s", path)
				shouldRestart = true
				break
			}
		}

		if shouldRestart {
			shouldRestart = false
			restartChan <- true
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type Status struct {
	InstanceUptime time.Duration
	AppUptime      time.Duration
	AppVersion     int
}

func getInstanceStatus(instanceName string) (*Status, error) {
	client, err := createSSHClient(ipForInstance(instanceName), 5*time.Second)
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	output, err := session.CombinedOutput("/agent/agent status")
	if err != nil {
		return nil, err
	}
	status := &Status{}
	if err := json.Unmarshal(output, status); err != nil {
		return nil, err
	}
	return status, nil
}

func uploadAgent() {
	path, err := buildExecutable("github.com/pushbullet/engineer/agent", false)
	V(err)

	r, err := os.Open(path)
	V(err)
	gcsWrite("agent", r)
	V(r.Close())
}

func deployVersion() {
	path, err := buildExecutable(inst.App.Executable, false)
	V(err)

	infof("getting state")
	state, err := engineer.GetState(ctx, inst.Bucket())
	V(err)
	state.Version++

	infof("uploading files")
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	fw, err := zw.Create(filepath.Base(inst.App.Executable))
	V(err)
	r, err := os.Open(path)
	V(err)
	_, err = io.Copy(fw, r)
	V(err)

	V(zw.Close())
	gcsVersionWrite(state.Version, "package.zip", buf)

	if state.Version == 1 {
		gcsVersionWrite(state.Version, "env.json", strings.NewReader("{}"))
	} else {
		gcsVersionCopy(state.Version-1, state.Version, "env.json")
	}

	{
		j, err := json.Marshal(inst.App)
		V(err)
		gcsVersionWrite(state.Version, "app.json", bytes.NewReader(j))
	}

	infof("updating state")
	V(engineer.PutState(ctx, inst.Bucket(), state))

	infof("updating instances")
	sshInstances(getInstances(), "update")
	infof("deployed version=%d", state.Version)

	if state.Version == 1 {
		infof("running sync automatically for first deploy")
		syncResources(inst)
	}
}

func ipForInstance(instance string) string {
	resp, err := gce.Instances.Get(inst.Deployment.Project, inst.Deployment.Zone, instance).Do()
	V(err)
	return resp.NetworkInterfaces[0].AccessConfigs[0].NatIP
}

func sshInstances(instances []string, command string) {
	for _, instance := range instances {
		sshCommand(lastPathComponent(instance), "/agent/agent "+command)
	}
}

func wait(originalOp *compute.Operation, err error) {
	project := inst.Deployment.Project
	zone := inst.Deployment.Zone
	region := RegionFromZone(inst.Deployment.Zone)

	V(err)
	for {
		var op *compute.Operation
		var err error
		if originalOp.Zone != "" {
			op, err = gce.ZoneOperations.Get(project, zone, originalOp.Name).Do()
		} else if originalOp.Region != "" {
			op, err = gce.RegionOperations.Get(project, region, originalOp.Name).Do()
		} else {
			op, err = gce.GlobalOperations.Get(project, originalOp.Name).Do()
		}
		V(err)
		if op.Status == "DONE" {
			if op.Error != nil {
				for _, e := range op.Error.Errors {
					errorf("%s", e.Message)
				}
				os.Exit(1)
			}
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func getInstances() []string {
	resp, err := gce.Instances.List(inst.Deployment.Project, inst.Deployment.Zone).Filter(fmt.Sprintf("name eq '%s-[a-z0-9]{4}'", inst.InstanceBase())).Do()
	V(err)

	instances := []string{}
	for _, item := range resp.Items {
		instances = append(instances, item.Name)
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

func gcsWriter(name string) *storage.Writer {
	return storageClient.Bucket(inst.Bucket()).Object(name).NewWriter(ctx)
}

func gcsVersionCopy(oldVersion int, newVersion int, name string) {
	src := strconv.Itoa(oldVersion) + "/" + name
	dst := strconv.Itoa(newVersion) + "/" + name
	infof("copying gcs file src=gs://%s/%s dst=gs://%s/%s", inst.Bucket(), src, inst.Bucket(), dst)
	_, err := storageClient.CopyObject(ctx, inst.Bucket(), src, inst.Bucket(), dst, nil)
	V(err)
}

func gcsWrite(name string, r io.Reader) {
	start := time.Now()
	w := gcsWriter(name)
	n, err := io.Copy(w, r)
	V(err)
	V(w.Close())
	infof("wrote gcs file path=gs://%s/%s %d bytes in %.2fs", inst.Bucket(), name, n, time.Now().Sub(start).Seconds())
}

func gcsVersionWrite(version int, name string, r io.Reader) {
	gcsWrite(strconv.Itoa(version)+"/"+name, r)
}

func gcsDelete(name string) {
	infof("deleting gcs file path=gs://%s/%s", inst.Bucket(), name)
	err := storageClient.Bucket(inst.Bucket()).Object(name).Delete(ctx)
	if is404Error(err) {
		return
	}
	V(err)
}

func createSSHClient(ipAddress string, timeout time.Duration) (*ssh.Client, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	sshKeyPath := u.HomeDir + "/.ssh/engineer-" + inst.Deployment.Project

	if _, err := os.Stat(sshKeyPath); os.IsNotExist(err) {
		// generate a new key and add it to the metadata
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		block := pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}
		V(ioutil.WriteFile(sshKeyPath, pem.EncodeToMemory(&block), 0600))

		sshPublicKey, err := ssh.NewPublicKey(privateKey.Public())
		if err != nil {
			return nil, err
		}
		auth := ssh.MarshalAuthorizedKey(sshPublicKey)

		if err := ioutil.WriteFile(sshKeyPath+".pub", auth, 0644); err != nil {
			return nil, err
		}

		prj, err := gce.Projects.Get(inst.Deployment.Project).Do()
		if err != nil {
			return nil, err
		}

		key := "root:" + string(auth)
		found := false
		for _, item := range prj.CommonInstanceMetadata.Items {
			if item.Key == "sshKeys" {
				found = true
				keys := strings.Split(strings.TrimSpace(*item.Value), "\n")
				v := strings.Join(append(keys, key), "\n")
				item.Value = &v
				break
			}
		}

		if !found {
			prj.CommonInstanceMetadata.Items = append(prj.CommonInstanceMetadata.Items, &compute.MetadataItems{Key: "sshKeys", Value: &key})
		}

		wait(gce.Projects.SetCommonInstanceMetadata(inst.Deployment.Project, prj.CommonInstanceMetadata).Do())
	}

	keyBytes, err := ioutil.ReadFile(sshKeyPath)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
	}

	conn, err := net.DialTimeout("tcp", ipAddress+":22", timeout)
	if err != nil {
		return nil, err
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, ipAddress+":22", config)
	if err != nil {
		return nil, err
	}

	return ssh.NewClient(c, chans, reqs), nil
}

func sshCommand(instance string, command string) {
	infof("running ssh command %s: %s", instance, command)

	client, err := createSSHClient(ipForInstance(instance), 5*time.Second)
	V(err)
	session, err := client.NewSession()
	V(err)
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		errorf("ssh output: %s", output)
	}
	V(err)
}

func getEnv(version int) (map[string]string, error) {
	r, err := storageClient.Bucket(inst.Bucket()).Object(strconv.Itoa(version) + "/env.json").NewReader(ctx)
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		return nil, err
	}
	return env, nil
}

func printEnv(env map[string]string) {
	for k, v := range env {
		fmt.Printf("  %s=%s\n", k, v)
	}
}

func RPartition(s string, sep string) (string, string) {
	i := strings.LastIndex(s, sep)
	if i == -1 {
		return s, ""
	}
	return s[:i], s[i+len(sep):]
}

func putEnv(version int, env map[string]string) {
	j, err := json.Marshal(env)
	V(err)
	gcsVersionWrite(version, "env.json", bytes.NewReader(j))
}

func lastPathComponent(u string) string {
	_, name := RPartition(u, "/")
	if name == "" {
		return u
	} else {
		return name
	}
}

func appCommand(command string, args []string) {
	bucket := storageClient.Bucket(inst.Bucket())
	_, err := bucket.Attrs(ctx)
	if err != nil && err != storage.ErrBucketNotExist {
		V(err)
	}
	bucketExists := err == nil

	if command != "deploy" && command != "destroy" && command != "logs" {
		if !bucketExists {
			exitf("missing app bucket name=%s", inst.Bucket())
		}
	}

	switch command {
	case "destroy":
		infof("destroying deployment=%s app=%s", inst.Deployment.Name, inst.App.Name)

		deleteResources(inst, listResources(inst))

		// if bucket exists, delete all items then delete the bucket
		// (bucket cannot be deleted unless all items are deleted, at least with this delete call)
		if bucketExists && ask("destroy the bucket "+inst.Bucket()+"?", false) {
			infof("deleting bucket name=%s", inst.Bucket())
			var query *storage.Query
			for {
				objects, err := bucket.List(ctx, query)
				V(err)
				for _, object := range objects.Results {
					bucket.Object(object.Name).Delete(ctx)
				}
				query = objects.Next
				if query == nil {
					break
				}
			}
			V(gcs.Buckets.Delete(inst.Bucket()).Do())
		}
	case "deploy":
		if !bucketExists {
			infof("creating environment name=%s project=%s", inst.Deployment.Name, inst.Deployment.Project)
			infof("creating bucket name=%s", inst.Bucket())
			_, err = gcs.Buckets.Insert(inst.Deployment.Project, &rawstorage.Bucket{Name: inst.Bucket()}).Do()
			V(err)
			gcsWrite("state.json", strings.NewReader("{}"))
		} else if err != nil {
			V(err)
		}

		deployVersion()
	case "sync":
		syncResources(inst)
	case "serve":
		serve()
	case "logs":
		V(exec.Command("open", fmt.Sprintf("https://console.developers.google.com/logs?project=%s&service=custom.googleapis.com&key1=%s", inst.Deployment.Project, inst.App.Name)).Run())
	case "status":
		infof("app:%s", inst.App.Name)
		state, err := engineer.GetState(ctx, inst.Bucket())
		V(err)
		infof("version:%d", state.Version)

		if !inst.App.Worker {
			forwardingRule, err := gce.ForwardingRules.Get(inst.Deployment.Project, RegionFromZone(inst.Deployment.Zone), inst.ForwardingRule()).Do()
			V(err)
			infof("ip:%s", forwardingRule.IPAddress)
		}

		igm, err := gce.InstanceGroupManagers.Get(inst.Deployment.Project, inst.Deployment.Zone, inst.InstanceGroup()).Do()
		V(err)
		parts := strings.Split(igm.InstanceTemplate, "-")
		infof("template_version:%s", parts[len(parts)-1])
		infof("target_size:%d", igm.TargetSize)

		instanceTemplate, err := gce.InstanceTemplates.Get(inst.Deployment.Project, lastPathComponent(igm.InstanceTemplate)).Do()
		V(err)
		infof("instance_type:%s", instanceTemplate.Properties.MachineType)

		result, err := gce.InstanceGroupManagers.ListManagedInstances(inst.Deployment.Project, inst.Deployment.Zone, inst.InstanceGroup()).Do()
		V(err)
		infof("instance_count:%d", len(result.ManagedInstances))

		infof("scopes:%v", instanceTemplate.Properties.ServiceAccounts[0].Scopes)
		tags := []string{}
		if instanceTemplate.Properties.Tags != nil {
			tags = instanceTemplate.Properties.Tags.Items
		}
		infof("tags:%v", tags)

		for _, instance := range result.ManagedInstances {
			instanceName := lastPathComponent(instance.Instance)
			result, err := gce.Instances.Get(inst.Deployment.Project, inst.Deployment.Zone, instanceName).Do()
			if is404Error(err) {
				continue
			}
			V(err)
			infof("\n%s", instanceName)

			instanceTemplate := ""
			for _, item := range result.Metadata.Items {
				if item.Key == "instance-template" {
					instanceTemplate = lastPathComponent(*item.Value)
					break
				}
			}
			parts := strings.Split(instanceTemplate, "-")
			infof("  template_version:%s", parts[len(parts)-1])
			infof("  status:%s", result.Status)

			if !inst.App.Worker {
				health, err := gce.TargetPools.GetHealth(inst.Deployment.Project, RegionFromZone(inst.Deployment.Zone), inst.TargetPool(), &compute.InstanceReference{Instance: instance.Instance}).Do()
				if err == nil {
					infof("  health:%+v", health.HealthStatus[0].HealthState)
				} else {
					infof("  health:UNKNOWN")
				}
			}

			created, err := time.Parse(time.RFC3339, result.CreationTimestamp)
			V(err)
			infof("  instance_age:%s", formatDuration(time.Now().Sub(created)))

			status, err := getInstanceStatus(instanceName)
			if err == nil {
				infof("  instance_uptime:%s", formatDuration(status.InstanceUptime))
				infof("  app_uptime:%s", formatDuration(status.AppUptime))
				infof("  app_version:%d", status.AppVersion)
			} else {
				infof("  instance_uptime:UNKNOWN")
				infof("  app_uptime:UNKNOWN")
				infof("  app_version:UNKNOWN")
			}
		}
	case "env", "setenv":
		state, err := engineer.GetState(ctx, inst.Bucket())
		V(err)
		if state.Version == 0 {
			exitf("no version deployed yet")
		}

		env, err := getEnv(state.Version)
		V(err)

		infof("old environment:")
		printEnv(env)

		switch command {
		case "env":
			printEnv(env)
			return
		case "setenv":
			if len(args) != 2 {
				exitf("you need to specify a key and a value to this command")
			}

			key := args[0]
			value := args[1]
			if strings.HasPrefix(value, "@") {
				// load from file
				contents, err := ioutil.ReadFile(value[1:])
				V(err)
				value = string(contents)
			}
			if value == "" {
				delete(env, key)
			} else {
				env[key] = value
			}
		}

		infof("new environment:")
		printEnv(env)

		infof("updating state")
		state.Version++
		gcsVersionCopy(state.Version-1, state.Version, "package.zip")
		gcsVersionCopy(state.Version-1, state.Version, "app.json")
		putEnv(state.Version, env)
		V(engineer.PutState(ctx, inst.Bucket(), state))

		infof("updating instances")
		sshInstances(getInstances(), "update")
		infof("deployed version=%d", state.Version)
	case "rollback":
		version, err := strconv.Atoi(args[0])
		if err != nil {
			exitf("version must be a number")
		}
		state, err := engineer.GetState(ctx, inst.Bucket())
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
		gcsVersionCopy(version, state.Version, "package.zip")
		gcsVersionCopy(version, state.Version, "app.json")
		gcsVersionCopy(version, state.Version, "env.json")
		V(engineer.PutState(ctx, inst.Bucket(), state))

		infof("updating instances")
		sshInstances(getInstances(), "update")
		infof("deployed version=%d", state.Version)
	case "run":
		state, err := engineer.GetState(ctx, inst.Bucket())
		V(err)
		if state.Version == 0 {
			exitf("no version deployed yet")
		}

		env, err := getEnv(state.Version)
		V(err)

		environment := []string{
			"GOPATH=" + os.Getenv("GOPATH"),
			"GOOGLE_APPLICATION_CREDENTIALS=" + os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"),
			"ENGR_PROJECT=" + inst.Deployment.Project,
			"ENGR_APP=" + inst.App.Name,
			"ENGR_VERSION=" + strconv.Itoa(state.Version),
		}

		for k, v := range env {
			environment = append(environment, fmt.Sprintf("%s=%s", k, v))
		}

		path, err := exec.LookPath(args[0])
		V(err)
		V(syscall.Exec(path, args, environment))
	default:
		exitf("invalid command=%s", command)
	}
}

func globalCommand(command string, args []string) {
	switch command {
	case "build-image":
		baseImageURL := ""
		scriptPath := ""
		// flag library requires that flags appear before the positional args, which messes up the existing commands
		for _, arg := range args {
			if arg[0] != '-' {
				exitf("invalid argument=%s", arg)
			}
			index := strings.Index(arg, "=")
			if index == -1 {
				exitf("invalid argument=%s", arg)
			}
			key := arg[1:index]
			value := arg[index+1:]
			switch key {
			case "script":
				scriptPath = value
			case "base-image-url":
				baseImageURL = value
			default:
				exitf("invalid argument=%s", arg)
			}
		}

		if baseImageURL == "" {
			imageList, err := gce.Images.List("debian-cloud").Filter("name eq 'debian-8-.*'").Do()
			V(err)
			for _, image := range imageList.Items {
				if image.Deprecated != nil {
					continue
				}
				baseImageURL = image.SelfLink
				break
			}
		}

		commands := []string{
			"apt-get update",
			"env DEBIAN_FRONTEND=noninteractive apt-get upgrade --yes --force-yes",
		}
		if scriptPath != "" {
			commands = []string{}
			file, err := os.Open(scriptPath)
			V(err)
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				commands = append(commands, scanner.Text())
			}
			V(scanner.Err())
			file.Close()
		}

		const (
			instanceName = "engr-build-image"
		)

		_, err := gce.Instances.Get(inst.Deployment.Project, inst.Deployment.Zone, instanceName).Do()
		if err == nil {
			infof("deleting existing instance")
			wait(gce.Instances.Delete(inst.Deployment.Project, inst.Deployment.Zone, instanceName).Do())
		} else if !is404Error(err) {
			V(err)
		}

		_, err = gce.Disks.Get(inst.Deployment.Project, inst.Deployment.Zone, instanceName).Do()
		if err == nil {
			infof("deleting existing disk")
			wait(gce.Disks.Delete(inst.Deployment.Project, inst.Deployment.Zone, instanceName).Do())
		} else if !is404Error(err) {
			V(err)
		}

		instance := &compute.Instance{
			MachineType: "zones/" + inst.Deployment.Zone + "/machineTypes/n1-standard-1",
			Name:        instanceName,
			Disks: []*compute.AttachedDisk{
				&compute.AttachedDisk{
					Boot:             true,
					InitializeParams: &compute.AttachedDiskInitializeParams{SourceImage: baseImageURL},
				},
			},
			NetworkInterfaces: []*compute.NetworkInterface{
				{
					Network: "global/networks/default",
					AccessConfigs: []*compute.AccessConfig{
						{
							Name: "External NAT",
						},
					},
				},
			},
		}

		infof("creating instance name=%s", instanceName)
		wait(gce.Instances.Insert(inst.Deployment.Project, inst.Deployment.Zone, instance).Do())

		client, err := createSSHClient(ipForInstance(instanceName), 60*time.Second)
		V(err)

		for _, command := range commands {
			s, err := client.NewSession()
			V(err)
			fmt.Printf("running command: %s\n", command)
			s.Stdout = os.Stdout
			s.Stderr = os.Stdout
			if err := s.Run(command); err != nil {
				errorf("ssh command failed err=%v", err)
			}
			s.Close()
		}

		infof("deleting instance")
		wait(gce.Instances.Delete(inst.Deployment.Project, inst.Deployment.Zone, instanceName).Do())

		imageName := "engr-image-" + time.Now().Format("20060102t150405")
		infof("creating image")
		image := &compute.Image{
			Name:       imageName,
			SourceDisk: fmt.Sprintf("zones/%s/disks/%s", inst.Deployment.Zone, instanceName),
		}
		wait(gce.Images.Insert(inst.Deployment.Project, image).Do())

		infof("deleting disk")
		wait(gce.Disks.Delete(inst.Deployment.Project, inst.Deployment.Zone, instanceName).Do())

		infof("created image=%s", imageName)
	default:
		exitf("invalid command=%s", command)
	}
}

func main() {
	var err error
	config := Config{}
	{
		contents, err := ioutil.ReadFile("engr.json")
		if err != nil {
			exitf("could not read engr.json")
		}

		if err := json.Unmarshal(contents, &config); err != nil {
			exitf("could not parse engr.json")
		}
	}

	args := os.Args[1:]

	if len(args) < 2 {
		fmt.Printf(`Usage: engr <deployment> <app> <command>

Where deployment and app are defined in "engr.json"
Command must be one of:

  serve - runs the app on the local machine with the environment of the app
  deploy - deploy a new version of the app or create the first version
    this command will cause a new version to be deployed
	sync - update server resources

  rollback <version> - rollback to the specified version
    this command will cause a new version to be deployed
  status - prints out the status of the app
  env - prints the current environment
  setenv <key> <value> - sets the value of a key to the provided string
			   <key> @<filename> - sets the value of a key to the contents of the file
				 <key> "" - removes the key
    this command will cause a new version to be deployed
	destroy - destroys all resources for the app
	run - run a script on the local machine with the environment of the app
	logs - open a browser window to show the logs for this app

Global commands:
Usage: engr <deployment> <command> [options]

	build-image - build an image starting from the specified base
	   image and using the provided script
		 options:
			 -base-image-url=<base image>
			   the default base image is debian-8
			 -script=<script>
			   the default script will install updates to all installed packages
`)
		return
	}

	{
		deploymentName := args[0]

		deployment, ok := config.Deployments[deploymentName]
		if !ok {
			exitf("invalid deployment name=%s", deploymentName)
		}
		deployment.Name = deploymentName

		inst = Install{
			Deployment: deployment,
		}
	}

	os.Setenv("ENGR_DEVELOPMENT", "1")
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", inst.Deployment.KeyPath)
	client, err := google.DefaultClient(oauth2.NoContext, "https://www.googleapis.com/auth/devstorage.read_write", "https://www.googleapis.com/auth/compute")
	if err != nil {
		exitf("could not find google account, make sure you have run `gcloud auth login`\nerr=%v", err)
	}
	gce, err = compute.New(client)
	V(err)
	gcs, err = rawstorage.New(client)
	V(err)

	// do a test request to see if our token is good
	if _, err := gcs.Buckets.List(inst.Deployment.Project).Do(); err != nil {
		exitf("google account does not seem to work, try running `gcloud auth login`\nerr=%v", err)
	}

	ctx = cloud.NewContext(inst.Deployment.Project, client)
	storageClient, err = storage.NewClient(ctx)
	V(err)

	start := time.Now()

	app, ok := config.Apps[args[1]]
	if ok || (len(args) > 2 && args[2] == "destroy") {
		app.Name = args[1]
		inst.App = app
		appCommand(args[2], args[3:])
		infof("elapsed: %.1fs", time.Now().Sub(start).Seconds())
	} else if args[1] == "build-image" {
		globalCommand(args[1], args[2:])
	} else {
		exitf("invalid app name=%s", args[1])
	}
}
