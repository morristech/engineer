package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	compute "google.golang.org/api/compute/v1"

	"golang.org/x/net/context"

	"github.com/pushbullet/engineer/internal"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
)

func listsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func retry(f func() error, minPeriod time.Duration, timeout time.Duration) error {
	var err error
	start := time.Now()
	for {
		attemptStart := time.Now()
		err = f()
		if err == nil {
			return nil
		}
		time.Sleep(minPeriod - time.Now().Sub(attemptStart))

		if time.Now().Sub(start) > timeout {
			return err
		}
	}
	return err
}

func ask(prompt string, defaultValue bool) bool {
	yn := "y/N"
	if defaultValue {
		yn = "Y/n"
	}

	for {
		fmt.Printf(Yellow+"%s [%s]: "+Reset, prompt, yn)

		response := ""
		b := make([]byte, 1)
		for {
			_, err := os.Stdin.Read(b)
			if b[0] == '\n' {
				break
			}
			response += string(b)
			if err == io.EOF {
				break
			}
			V(err)
		}

		if response == "" {
			return defaultValue
		} else {
			switch strings.ToLower(response) {
			case "y":
				return true
			case "n":
				return false
			default:
				errorf("invalid response")
			}
		}
	}
}

func wait(originalOp *compute.Operation, err error) {
	V(err)
	project := strings.Split(originalOp.SelfLink, "/")[6]
	for {
		var op *compute.Operation
		var err error
		if originalOp.Zone != "" {
			op, err = gce.ZoneOperations.Get(project, lastComponent(originalOp.Zone, "/"), originalOp.Name).Do()
		} else if originalOp.Region != "" {
			op, err = gce.RegionOperations.Get(project, lastComponent(originalOp.Region, "/"), originalOp.Name).Do()
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

func resourceExists(resp interface{}, err error) bool {
	if is404Error(err) {
		return false
	}
	V(err)
	return true
}

func createGlobalResources(app internal.App) {
	project := app.Project
	region := app.Region()

	{
		topic := internal.TopicFromAppName(pubsubClient, app.Name)
		exists, err := topic.Exists(ctx)
		V(err)
		if !exists {
			infof("creating topic %s", topic.ID())
			_, err := pubsubClient.CreateTopic(ctx, topic.ID())
			V(err)
			policy, err := topic.IAM().Policy(ctx)
			V(err)
			// https://cloud.google.com/pubsub/docs/access_control
			policy.Add("serviceAccount:"+app.ServiceAccountEmail(), "roles/pubsub.publisher")
			policy.Add("serviceAccount:"+app.ServiceAccountEmail(), "roles/pubsub.subscriber")
			policy.Add("serviceAccount:"+app.ServiceAccountEmail(), "roles/pubsub.viewer")
			V(topic.IAM().SetPolicy(ctx, policy))
		}
	}

	if !app.Server {
		return
	}

	{
		name := app.HealthCheck()
		if !resourceExists(gce.HttpHealthChecks.Get(project, name).Do()) {
			healthCheck := &compute.HttpHealthCheck{
				Name: name,
				Port: 8080,
			}
			infof("creating health check %s", name)
			wait(gce.HttpHealthChecks.Insert(project, healthCheck).Do())
		}
	}

	{
		name := app.TargetPool()
		if !resourceExists(gce.TargetPools.Get(project, region, name).Do()) {
			infof("creating target pool %s", name)
			targetPool := &compute.TargetPool{
				Name:         name,
				HealthChecks: []string{fmt.Sprintf("global/httpHealthChecks/%s", app.HealthCheck())},
			}
			wait(gce.TargetPools.Insert(project, region, targetPool).Do())
		}
	}

	{
		name := app.Address()
		if !resourceExists(gce.Addresses.Get(project, region, name).Do()) {
			infof("creating static ip address %s", name)
			address := &compute.Address{
				Name: name,
			}
			wait(gce.Addresses.Insert(project, region, address).Do())
		}
	}

	{
		name := app.ForwardingRule()
		if !resourceExists(gce.ForwardingRules.Get(project, region, name).Do()) {
			address, err := gce.Addresses.Get(project, region, app.Address()).Do()
			V(err)

			infof("creating forwarding rule %s", name)
			forwardingRule := &compute.ForwardingRule{
				Name:       name,
				IPProtocol: "TCP",
				IPAddress:  address.Address,
				Target:     fmt.Sprintf("regions/%s/targetPools/%s", region, app.TargetPool()),
			}
			wait(gce.ForwardingRules.Insert(project, region, forwardingRule).Do())
		}
	}

	for _, tag := range app.Tags {
		if tag == "http-server" || tag == "https-server" {
			suffix := "http"
			port := "80"
			if tag == "https-server" {
				suffix = "https"
				port = "443"
			}

			if !resourceExists(gce.Firewalls.Get(project, "default-allow-"+suffix).Do()) {
				firewall := &compute.Firewall{
					Name: "default-allow-" + suffix,
					Allowed: []*compute.FirewallAllowed{
						&compute.FirewallAllowed{
							IPProtocol: "tcp",
							Ports:      []string{port},
						},
					},
					SourceRanges: []string{"0.0.0.0/0"},
					TargetTags:   []string{tag},
				}
				wait(gce.Firewalls.Insert(project, firewall).Do())
			}
		}
	}
}

func destroyGlobalResources(app internal.App) {
	{
		topic := internal.TopicFromAppName(pubsubClient, app.Name)
		exists, err := topic.Exists(ctx)
		V(err)
		if exists {
			infof("destroying topic %s", topic.ID())
			V(topic.Delete(ctx))
		}
	}

	{
		name := app.ForwardingRule()
		if resourceExists(gce.ForwardingRules.Get(app.Project, app.Region(), name).Do()) {
			infof("destroying forwarding rule %s", name)
			wait(gce.ForwardingRules.Delete(app.Project, app.Region(), name).Do())
		}
	}

	{
		name := app.Address()
		if resourceExists(gce.Addresses.Get(app.Project, app.Region(), name).Do()) {
			infof("destroying static ip address %s", name)
			wait(gce.Addresses.Delete(app.Project, app.Region(), name).Do())
		}
	}

	{
		name := app.TargetPool()
		if resourceExists(gce.TargetPools.Get(app.Project, app.Region(), name).Do()) {
			infof("destroying target pool %s", name)
			wait(gce.TargetPools.Delete(app.Project, app.Region(), name).Do())
		}
	}

	{
		name := app.HealthCheck()
		if resourceExists(gce.HttpHealthChecks.Get(app.Project, name).Do()) {
			infof("destroying health check %s", name)
			wait(gce.HttpHealthChecks.Delete(app.Project, name).Do())
		}
	}
}

func getImageURL(app internal.App) string {
	if app.Image != "" {
		customImageURL := fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/global/images/%s", app.Project, app.Image)
		if !resourceExists(gce.Images.Get(app.Project, app.Image).Do()) {
			exitf("image %s not found", app.Image)
		}
		return customImageURL
	}

	imageList, err := gce.Images.List("debian-cloud").Filter("name eq 'debian-8-.*'").Do()
	V(err)
	for _, image := range imageList.Items {
		if image.Deprecated != nil {
			continue
		}
		return image.SelfLink
	}
	exitf("no image specified for app and could not find debian-8 image to use instead")
	return ""
}

func generateStartupScript(app internal.App) string {
	return fmt.Sprintf(`#!/bin/sh
# retry setup every 30 seconds until successful
while true
do
mkdir /agent
gsutil cp gs://%s/agent-%s /agent/agent
chmod +x /agent/agent
/agent/agent setup
if [ $? -eq 0 ]
then
exit 0
fi
sleep 30
done`, app.Bucket(), agentVersion)
}

func uploadAgent(app internal.App) {
	_, err := storageClient.Bucket(app.Bucket()).Object("agent-" + agentVersion).Attrs(ctx)
	if err == storage.ErrObjectNotExist {
		gopath, err := findGOPATH()
		V(err)
		agentBinary, err := ioutil.ReadFile(filepath.Join(gopath, "src/github.com/pushbullet/engineer/resources/agent"))
		V(err)
		gcsWrite(app, "agent-"+agentVersion, bytes.NewReader(agentBinary))
	}
}

func createInstanceGroup(app internal.App, version int, singleton bool) {
	appVersion := strconv.Itoa(version)

	imageURL := getImageURL(app)

	// make sure the newest agent is uploaded
	uploadAgent(app)

	// create a new instance group
	if resourceExists(gce.InstanceGroupManagers.Get(app.Project, app.Zone, app.InstanceGroup(version)).Do()) {
		exitf("instance group manager %s already exists, please delete it first", app.InstanceGroup(version))
	}

	if resourceExists(gce.InstanceTemplates.Get(app.Project, app.Template(version)).Do()) {
		// delete the old template
		wait(gce.InstanceTemplates.Delete(app.Project, app.Template(version)).Do())
	}

	bucket := app.Bucket()

	startupScript := generateStartupScript(app)

	tmpl := &compute.InstanceTemplate{
		Name: app.Template(version),
		Properties: &compute.InstanceProperties{
			MachineType: app.MachineType,
			Tags:        &compute.Tags{Items: app.Tags},
			Disks: []*compute.AttachedDisk{
				{
					AutoDelete: true,
					Boot:       true,
					InitializeParams: &compute.AttachedDiskInitializeParams{
						SourceImage: imageURL,
					},
				},
			},
			Metadata: &compute.Metadata{
				Items: []*compute.MetadataItems{
					{
						Key:   "app",
						Value: &app.Name,
					},
					{
						Key:   "app-version",
						Value: &appVersion,
					},
					{
						Key:   "bucket",
						Value: &bucket,
					},
					{
						Key:   "agent-version",
						Value: &agentVersion,
					},
					{
						Key:   "startup-script",
						Value: &startupScript,
					},
				},
			},
			NetworkInterfaces: []*compute.NetworkInterface{
				{
					Network: "global/networks/default",
					AccessConfigs: []*compute.AccessConfig{
						{
							Type: "ONE_TO_ONE_NAT",
							Name: "External NAT",
						},
					},
				},
			},
			Scheduling: &compute.Scheduling{AutomaticRestart: true},
			ServiceAccounts: []*compute.ServiceAccount{
				{
					Email:  app.ServiceAccountEmail(),
					Scopes: []string{"https://www.googleapis.com/auth/cloud-platform", "https://www.googleapis.com/auth/userinfo.email"},
				},
			},
		},
	}

	infof("creating instance template %s", tmpl.Name)
	wait(gce.InstanceTemplates.Insert(app.Project, tmpl).Do())

	name := app.InstanceGroup(version)
	baseInstanceName := app.InstanceBase(version)
	if singleton {
		name = app.InstanceGroupSingleton()
		baseInstanceName = app.InstanceBaseSingleton()
	}

	instanceGroupManager := &compute.InstanceGroupManager{
		Name:             name,
		BaseInstanceName: baseInstanceName,
		TargetSize:       int64(app.InstanceCount),
		InstanceTemplate: fmt.Sprintf("global/instanceTemplates/%s", tmpl.Name),
	}

	if app.Server {
		instanceGroupManager.TargetPools = []string{fmt.Sprintf("regions/%s/targetPools/%s", app.Region(), app.TargetPool())}
	}

	infof("creating instance group %s", instanceGroupManager.Name)
	wait(gce.InstanceGroupManagers.Insert(app.Project, app.Zone, instanceGroupManager).Do())
	waitForInstanceGroup(app, instanceGroupManager.Name)
}

// func offlineInstanceGroup(app internal.App, name string) {
// 	tc, _ := context.WithTimeout(ctx, 15*time.Second)
// 	msgs, err := RPC(tc, app.Name, internal.CommandOffline, 0, len(getInstances(app, igm.Name)), pubsubClient)
// 	if err != context.DeadlineExceeded {
// 		V(err)
// 	}
// }

func destroyInstanceGroup(app internal.App, name string) {
	igm, err := gce.InstanceGroupManagers.Get(app.Project, app.Zone, name).Do()
	if is404Error(err) {
		return
	}
	V(err)

	// make sure this is not the only instance group
	resp, err := gce.InstanceGroupManagers.List(app.Project, app.Zone).Filter(fmt.Sprintf(`name eq '%s-group.*'`, app.Name)).Do()
	V(err)
	if len(resp.Items) == 1 {
		if !ask("destroy last instance group for "+app.Name+"?", false) {
			return
		}
	}

	infof("destroying instance group %s", name)
	wait(gce.InstanceGroupManagers.Delete(app.Project, app.Zone, name).Do())

	groupTemplate := lastComponent(igm.InstanceTemplate, "/")
	infof("destroying instance group template %s", groupTemplate)
	wait(gce.InstanceTemplates.Delete(app.Project, groupTemplate).Do())
}

func updateSingletonInstanceGroup(app internal.App, version int) {
	name := app.InstanceGroupSingleton()

	igm, err := gce.InstanceGroupManagers.Get(app.Project, app.Zone, name).Do()
	V(err)

	waitForInstanceGroup(app, name)

	migrate := false
	instanceTemplate, err := gce.InstanceTemplates.Get(app.Project, lastComponent(igm.InstanceTemplate, "/")).Do()
	V(err)
	props := instanceTemplate.Properties
	if props.MachineType != app.MachineType {
		infof("changing machine type from %s to %s", props.MachineType, app.MachineType)
		migrate = true
		props.MachineType = app.MachineType
	}

	for _, item := range props.Metadata.Items {
		if item.Key == "app-version" {
			appVersion := strconv.Itoa(version)
			item.Value = &appVersion
			break
		}
	}

	existingAgentVersion := ""
	for _, item := range props.Metadata.Items {
		if item.Key == "agent-version" {
			existingAgentVersion = *item.Value
			break
		}
	}

	if existingAgentVersion != agentVersion {
		infof("upgrading agent from version %s to version %s", existingAgentVersion, agentVersion)
		uploadAgent(app)
		migrate = true
		for _, item := range props.Metadata.Items {
			if item.Key == "agent-version" {
				item.Value = &agentVersion
			}
			if item.Key == "startup-script" {
				startupScript := generateStartupScript(app)
				item.Value = &startupScript
			}
		}
	}

	existingTags := []string{}
	if props.Tags != nil {
		existingTags = props.Tags.Items
	}
	sort.Strings(existingTags)
	tags := app.Tags
	sort.Strings(tags)

	if !listsEqual(existingTags, tags) {
		infof("changing tags from %v to %v", existingTags, tags)
		migrate = true
		props.Tags = &compute.Tags{Items: tags}
	}

	var bootDisk *compute.AttachedDisk
	for _, disk := range props.Disks {
		if disk.Boot {
			bootDisk = disk
			break
		}
	}

	imageURL := getImageURL(app)

	if bootDisk.InitializeParams.SourceImage != imageURL {
		infof("changing image url from %s to %s", bootDisk.InitializeParams.SourceImage, imageURL)
		migrate = true
		bootDisk.InitializeParams.SourceImage = imageURL
	}

	instanceTemplate.Name = app.Template(version)
	infof("creating new template %s", instanceTemplate.Name)

	// delete any existing template with this name
	if resourceExists(gce.InstanceTemplates.Get(app.Project, instanceTemplate.Name).Do()) {
		wait(gce.InstanceTemplates.Delete(app.Project, instanceTemplate.Name).Do())
	}

	wait(gce.InstanceTemplates.Insert(app.Project, instanceTemplate).Do())

	infof("updating instance group %s", name)
	req := &compute.InstanceGroupManagersSetInstanceTemplateRequest{
		InstanceTemplate: fmt.Sprintf("global/instanceTemplates/%s", instanceTemplate.Name),
	}
	wait(gce.InstanceGroupManagers.SetInstanceTemplate(app.Project, app.Zone, name, req).Do())

	if migrate {
		migrateInstances(app)
	}

	igm, err = gce.InstanceGroupManagers.Get(app.Project, app.Zone, name).Do()
	V(err)
	if igm.TargetSize != int64(app.InstanceCount) {
		infof("resizing from %d to %d instances", igm.TargetSize, app.InstanceCount)
		wait(gce.InstanceGroupManagers.Resize(app.Project, app.Zone, name, int64(app.InstanceCount)).Do())
		waitForInstanceGroup(app, name)
	}
}

func deployApp(app internal.App, version int) {
	if app.StagedDeploy {
		createInstanceGroup(app, version, false)
		if resourceExists(gce.InstanceGroupManagers.Get(app.Project, app.Zone, app.InstanceGroupSingleton()).Do()) {
			destroyInstanceGroup(app, app.InstanceGroupSingleton())
		}
	} else {
		if resourceExists(gce.InstanceGroupManagers.Get(app.Project, app.Zone, app.InstanceGroupSingleton()).Do()) {
			// would be nice if I could parallelize the deploy somehow
			updateSingletonInstanceGroup(app, version)

			count := len(getInstances(app, app.InstanceGroupSingleton()))
			infof("updating %d instances", count)

			tc, _ := context.WithTimeout(ctx, 15*time.Second)
			msgs, err := RPC(tc, app.Name, internal.CommandUpdate, version, count, pubsubClient)
			if err == context.DeadlineExceeded {
				errorf("timed out waiting for some responses")
			} else {
				V(err)
			}
			for _, msg := range msgs {
				if msg.Error != "" {
					errorf("instance reported error=%s", msg.Error)
				}
			}
		} else {
			createInstanceGroup(app, version, true)
		}

		// cleanup old instance groups
		igms, err := gce.InstanceGroupManagers.List(app.Project, app.Zone).Filter(fmt.Sprintf(`name eq '%s-group-\d+'`, app.Name)).Do()
		V(err)
		for _, igm := range igms.Items {
			destroyInstanceGroup(app, igm.Name)
		}
	}

	// delete all unused templates
	templates, err := gce.InstanceTemplates.List(app.Project).Filter(fmt.Sprintf(`name eq '%s-template-\d+'`, app.Name)).Do()
	V(err)
	for _, template := range templates.Items {
		// skip the current template
		if template.Name == app.Template(version) {
			continue
		}
		_, err := gce.InstanceTemplates.Delete(app.Project, template.Name).Do()
		resourceInUse := false
		if err != nil {
			if e, ok := err.(*googleapi.Error); ok {
				if e.Code == 400 && len(e.Errors) > 0 && e.Errors[0].Reason == "resourceInUseByAnotherResource" {
					resourceInUse = true
				}
			}

			if !resourceInUse {
				V(err)
			}
		}
		if !resourceInUse {
			infof("destroying instance group template %s", template.Name)
		}
	}
}

func updateRoles(app internal.App) {
	policy, err := crm.Projects.GetIamPolicy(app.Project, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	V(err)

	// https://cloud.google.com/iam/docs/understanding-roles
	defaultRoles := []string{
		"roles/logging.logWriter",
		"roles/pubsub.editor",
	}

	if app.Debug {
		defaultRoles = append(defaultRoles, "roles/clouddebugger.agent")
	}

	roles := app.Roles
	for _, role := range defaultRoles {
		roles = append(roles, role)
	}

	existingRoles := []string{}

	// remove all roles for the account, we will add them back below
	for _, binding := range policy.Bindings {
		for i, member := range binding.Members {
			if member == "serviceAccount:"+app.ServiceAccountEmail() {
				existingRoles = append(existingRoles, binding.Role)
				binding.Members = append(binding.Members[:i], binding.Members[i+1:]...)
				break
			}
		}
	}

	sort.Strings(roles)
	sort.Strings(existingRoles)
	if listsEqual(roles, existingRoles) {
		return
	}

	// add all roles for this account
	for _, role := range roles {
		found := false
		for _, binding := range policy.Bindings {
			if binding.Role == role {
				found = true
				binding.Members = append(binding.Members, "serviceAccount:"+app.ServiceAccountEmail())
			}
		}

		if !found {
			binding := &cloudresourcemanager.Binding{
				Members: []string{"serviceAccount:" + app.ServiceAccountEmail()},
				Role:    role,
			}
			policy.Bindings = append(policy.Bindings, binding)
		}
	}

	policyRequest := &cloudresourcemanager.SetIamPolicyRequest{Policy: policy}
	_, err = crm.Projects.SetIamPolicy(app.Project, policyRequest).Do()
	V(err)
}

func waitForInstanceGroup(app internal.App, name string) {
	f := func() error {
		result, err := gce.InstanceGroupManagers.ListManagedInstances(app.Project, app.Zone, name).Do()
		if err != nil {
			return err
		}
		for _, instance := range result.ManagedInstances {
			if instance.CurrentAction != "NONE" {
				return errors.New("instance not ready")
			}
		}
		return nil
	}
	if f() != nil {
		infof("waiting for all instances in instance group %s to be available", name)
		V(retry(f, 5*time.Second, 5*time.Minute))
		infof("all instances available")
	}
}

func migrateInstances(app internal.App) {
	name := app.InstanceGroupSingleton()

	waitForInstanceGroup(app, name)

	igm, err := gce.InstanceGroupManagers.Get(app.Project, app.Zone, name).Do()
	V(err)
	groupTemplate := lastComponent(igm.InstanceTemplate, "/")

	result, err := gce.InstanceGroupManagers.ListManagedInstances(app.Project, app.Zone, name).Do()
	V(err)

	goodInstances := []string{}
	badInstances := []string{}

	for _, instance := range result.ManagedInstances {
		instanceName := lastComponent(instance.Instance, "/")
		result, err := gce.Instances.Get(app.Project, app.Zone, instanceName).Do()
		V(err)

		instanceTemplate := ""
		for _, item := range result.Metadata.Items {
			if item.Key == "instance-template" {
				instanceTemplate = lastComponent(*item.Value, "/")
				break
			}
		}

		if instanceTemplate == "" {
			exitf("found instance in instance group without a template")
		}

		if instanceTemplate == groupTemplate {
			goodInstances = append(goodInstances, instance.Instance)
		} else {
			badInstances = append(badInstances, instance.Instance)
		}
	}

	if len(goodInstances) < app.InstanceCount {
		newInstances := app.InstanceCount - len(goodInstances)
		infof("creating new instances count=%d", newInstances)
		wait(gce.InstanceGroupManagers.Resize(app.Project, app.Zone, name, igm.TargetSize+int64(newInstances)).Do())
		waitForInstanceGroup(app, name)
	}

	if len(badInstances) > 0 {
		infof("removing old instances count=%d", len(badInstances))
		req := &compute.InstanceGroupManagersDeleteInstancesRequest{
			Instances: badInstances,
		}
		wait(gce.InstanceGroupManagers.DeleteInstances(app.Project, app.Zone, name, req).Do())
		waitForInstanceGroup(app, name)
	}
}
