package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"
)

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

func listResources(inst Install) []string {
	project := inst.Deployment.Project
	region := RegionFromZone(inst.Deployment.Zone)
	zone := inst.Deployment.Zone

	nameFilter := fmt.Sprintf("name eq '%s-%s-.*'", inst.Deployment.Name, inst.App.Name)

	resources := []string{}
	{
		resp, err := gce.Addresses.List(project, region).Filter(nameFilter).Do()
		V(err)
		for _, item := range resp.Items {
			resources = append(resources, item.Name)
		}
	}

	{
		resp, err := gce.TargetPools.List(project, region).Filter(nameFilter).Do()
		V(err)
		for _, item := range resp.Items {
			resources = append(resources, item.Name)
		}
	}

	{
		resp, err := gce.ForwardingRules.List(project, region).Filter(nameFilter).Do()
		V(err)
		for _, item := range resp.Items {
			resources = append(resources, item.Name)
		}
	}

	{
		resp, err := gce.InstanceGroupManagers.List(project, zone).Filter(nameFilter).Do()
		V(err)

		for _, item := range resp.Items {
			resources = append(resources, item.Name)
		}
	}

	{
		resp, err := gce.HttpHealthChecks.List(project).Filter(nameFilter).Do()
		V(err)

		for _, item := range resp.Items {
			resources = append(resources, item.Name)
		}
	}

	{
		resp, err := gce.InstanceTemplates.List(project).Filter(fmt.Sprintf(`name eq '%s-\d+'`, inst.TemplateBase())).Do()
		V(err)
		for _, item := range resp.Items {
			resources = append(resources, item.Name)
		}
	}
	return resources
}

func deleteResources(inst Install, resources []string) {
	if len(resources) == 0 {
		return
	}

	project := inst.Deployment.Project
	region := RegionFromZone(inst.Deployment.Zone)
	zone := inst.Deployment.Zone

	for _, name := range resources {
		warningf("will delete resource name=%s", name)
	}

	if !ask("destroy those resources?", false) {
		return
	}

	for _, s1 := range []string{"group", "rule", "address", "pool", "check"} {
		for _, name := range resources {
			_, s2 := RPartition(name, "-")
			if s1 == s2 {
				switch s1 {
				case "group":
					infof("deleting managed instance group name=%s", name)
					wait(gce.InstanceGroupManagers.Delete(project, zone, name).Do())
				case "rule":
					infof("deleting forwarding rule name=%s", name)
					wait(gce.ForwardingRules.Delete(project, region, name).Do())
				case "address":
					infof("deleting address name=%s", name)
					wait(gce.Addresses.Delete(project, region, name).Do())
				case "pool":
					infof("deleting target pool name=%s", name)
					wait(gce.TargetPools.Delete(project, region, name).Do())
				case "check":
					infof("deleting health check name=%s", name)
					wait(gce.HttpHealthChecks.Delete(project, name).Do())
				default:
					errorf("unrecognized resource name=%s", name)
				}
			}
		}
	}

	// templates don't use the same suffix
	for _, name := range resources {
		matched, err := regexp.MatchString(fmt.Sprintf(`%s-\d+`, inst.TemplateBase()), name)
		V(err)
		if matched {
			infof("deleting instance template name=%s", name)
			wait(gce.InstanceTemplates.Delete(project, name).Do())
		}
	}
}

func syncResources(inst Install) {
	infof("syncing resources")

	infof("finding existing resources")

	resourceExists := map[string]bool{}
	resourceUsed := map[string]bool{}
	for _, resource := range listResources(inst) {
		resourceExists[resource] = true
		resourceUsed[resource] = false
	}

	project := inst.Deployment.Project
	region := RegionFromZone(inst.Deployment.Zone)
	zone := inst.Deployment.Zone

	infof("creating/updating resources")

	if !inst.App.Worker {
		{
			name := inst.HealthCheck()
			resourceUsed[name] = true
			if !resourceExists[name] {
				healthCheck := &compute.HttpHealthCheck{
					Name: name,
					Port: 8080,
				}
				infof("creating health check name=%s", name)
				wait(gce.HttpHealthChecks.Insert(project, healthCheck).Do())
			}
		}

		{
			name := inst.TargetPool()
			resourceUsed[name] = true
			if !resourceExists[name] {
				targetPool := &compute.TargetPool{
					Name:         name,
					HealthChecks: []string{fmt.Sprintf("global/httpHealthChecks/%s", inst.HealthCheck())},
				}
				infof("creating target pool name=%s", targetPool.Name)
				wait(gce.TargetPools.Insert(project, region, targetPool).Do())
			}
		}

		{
			name := inst.Address()
			resourceUsed[name] = true
			if !resourceExists[name] {
				address := &compute.Address{
					Name: name,
				}
				infof("creating static ip address name=%s", address.Name)
				wait(gce.Addresses.Insert(project, region, address).Do())
			}
		}

		{
			name := inst.ForwardingRule()
			resourceUsed[name] = true
			if !resourceExists[name] {
				address, err := gce.Addresses.Get(project, region, inst.Address()).Do()
				V(err)

				forwardingRule := &compute.ForwardingRule{
					Name:       name,
					IPProtocol: "TCP",
					IPAddress:  address.Address,
					Target:     fmt.Sprintf("regions/%s/targetPools/%s", region, inst.TargetPool()),
				}

				infof("creating forwarding rule name=%s", forwardingRule.Name)
				wait(gce.ForwardingRules.Insert(project, region, forwardingRule).Do())
			}
		}
	}

	{
		name := inst.InstanceGroup()
		dc := inst.DeploymentConfig()

		resourceUsed[name] = true
		for tmpl := range resourceExists {
			if strings.HasPrefix(tmpl, inst.TemplateBase()+"-") {
				resourceUsed[tmpl] = true
			}
		}

		imageURL := ""
		if inst.Deployment.Image == "" {
			imageList, err := gce.Images.List("debian-cloud").Filter("name eq 'debian-8-.*'").Do()
			V(err)
			for _, image := range imageList.Items {
				if image.Deprecated != nil {
					continue
				}
				imageURL = image.SelfLink
				break
			}
		} else {
			imageURL = fmt.Sprintf("global/images/%s", inst.Deployment.Image)
		}

		scopes := []string{
			"https://www.googleapis.com/auth/devstorage.read_only",
			"https://www.googleapis.com/auth/logging.write",
		}

		if len(inst.App.Scopes) > 0 {
			for _, scope := range inst.App.Scopes {
				scopes = append(scopes, scope)
			}
		}

		if resourceExists[name] {
			// the instance group manager exists, it may require updating
			igm, err := gce.InstanceGroupManagers.Get(project, zone, name).Do()
			V(err)

			migrateInstances(inst)

			update := false
			instanceTemplate, err := gce.InstanceTemplates.Get(project, lastPathComponent(igm.InstanceTemplate)).Do()
			V(err)
			props := instanceTemplate.Properties
			if props.MachineType != dc.MachineType {
				infof("changing machine type from %s to %s", props.MachineType, dc.MachineType)
				update = true
				props.MachineType = dc.MachineType
			}

			existingAgentVersion := 0
			for _, item := range props.Metadata.Items {
				if item.Key == "agent-version" {
					existingAgentVersion, _ = strconv.Atoi(*item.Value)
					break
				}
			}

			if existingAgentVersion < agentVersion {
				infof("upgrading agent from version %d to version %d", existingAgentVersion, agentVersion)
				uploadAgent()
				update = true
				for _, item := range props.Metadata.Items {
					if item.Key == "agent-version" {
						agentVersionString := strconv.Itoa(agentVersion)
						item.Value = &agentVersionString
						break
					}
				}
			}

			existingScopes := props.ServiceAccounts[0].Scopes
			// compare scope lists as sets
			sort.Strings(existingScopes)
			sort.Strings(scopes)

			listsEqual := func(a, b []string) bool {
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

			if !listsEqual(existingScopes, scopes) {
				infof("changing scopes from %v to %v", existingScopes, scopes)
				update = true
				props.ServiceAccounts[0].Scopes = scopes
			}

			existingTags := []string{}
			if props.Tags != nil {
				existingTags = props.Tags.Items
			}
			sort.Strings(existingTags)
			tags := inst.App.Tags
			sort.Strings(tags)

			if !listsEqual(existingTags, tags) {
				infof("changing tags from %v to %v", existingTags, tags)
				update = true
				props.Tags = &compute.Tags{Items: tags}
			}

			var bootDisk *compute.AttachedDisk
			for _, disk := range props.Disks {
				if disk.Boot {
					bootDisk = disk
					break
				}
			}

			if bootDisk.InitializeParams.SourceImage != imageURL {
				infof("changing image url from %s to %s", bootDisk.InitializeParams.SourceImage, imageURL)
				update = true
				bootDisk.InitializeParams.SourceImage = imageURL
			}

			if update {
				infof("updating instance group name=%s", name)
				_, currentVersionString := RPartition(instanceTemplate.Name, "-")
				currentVersion, err := strconv.Atoi(currentVersionString)
				V(err)
				instanceTemplate.Name = inst.TemplateBase() + "-" + strconv.Itoa(currentVersion+1)
				infof("creating new template name=%s", instanceTemplate.Name)

				// delete any existing template with this name
				existingTemplate, err := gce.InstanceTemplates.Get(project, instanceTemplate.Name).Do()
				if is404Error(err) {
					// nothing to do here
				} else if err == nil {
					// delete the old template
					wait(gce.InstanceTemplates.Delete(project, existingTemplate.Name).Do())
				} else {
					V(err)
				}

				wait(gce.InstanceTemplates.Insert(project, instanceTemplate).Do())

				req := &compute.InstanceGroupManagersSetInstanceTemplateRequest{
					InstanceTemplate: fmt.Sprintf("global/instanceTemplates/%s", instanceTemplate.Name),
				}
				wait(gce.InstanceGroupManagers.SetInstanceTemplate(project, zone, name, req).Do())

				migrateInstances(inst)
			}
		} else {
			// create a new instance group
			startupScript := fmt.Sprintf(`#!/bin/sh
# retry setup every 30 seconds until successful
while true
do
  mkdir /agent
  gsutil cp gs://%s/agent /agent/agent
  chmod +x /agent/agent
  /agent/agent setup
  if [ $? -eq 0 ]
  then
    exit 0
  fi
  sleep 30
done`, inst.Bucket())

			bucket := inst.Bucket()

			uploadAgent()
			agentVersionString := strconv.Itoa(agentVersion)

			tmpl := &compute.InstanceTemplate{
				Name: inst.TemplateBase() + "-1",
				Properties: &compute.InstanceProperties{
					MachineType: dc.MachineType,
					Tags:        &compute.Tags{Items: inst.App.Tags},
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
								Value: &inst.App.Name,
							},
							{
								Key:   "bucket",
								Value: &bucket,
							},
							{
								Key:   "agent-version",
								Value: &agentVersionString,
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
									Name: "External NAT",
								},
							},
						},
					},
					Scheduling: &compute.Scheduling{AutomaticRestart: true},
					ServiceAccounts: []*compute.ServiceAccount{
						{
							Email:  "default",
							Scopes: scopes,
						},
					},
				},
			}

			infof("creating instance template name=%s", tmpl.Name)
			wait(gce.InstanceTemplates.Insert(project, tmpl).Do())

			instanceGroupManager := &compute.InstanceGroupManager{
				Name:             name,
				BaseInstanceName: inst.InstanceBase(),
				TargetSize:       int64(dc.InstanceCount),
				InstanceTemplate: fmt.Sprintf("global/instanceTemplates/%s", tmpl.Name),
			}

			if !inst.App.Worker {
				instanceGroupManager.TargetPools = []string{fmt.Sprintf("regions/%s/targetPools/%s", region, inst.TargetPool())}
			}

			infof("creating managed instance group name=%s", instanceGroupManager.Name)
			wait(gce.InstanceGroupManagers.Insert(project, zone, instanceGroupManager).Do())

			infof("waiting for instances to start")
			waitForInstanceGroup(inst)

			if !inst.App.Worker {
				address, err := gce.Addresses.Get(project, region, inst.Address()).Do()
				V(err)
				infof("app created ip=%s", address.Address)
			}
		}
	}

	infof("deleting resources")

	resourcesToDelete := []string{}
	for name, used := range resourceUsed {
		if !used {
			resourcesToDelete = append(resourcesToDelete, name)
		}
	}

	if len(resourcesToDelete) > 0 {
		deleteResources(inst, resourcesToDelete)
	}
}

func waitForInstanceGroup(inst Install) {
	f := func() error {
		result, err := gce.InstanceGroupManagers.ListManagedInstances(inst.Deployment.Project, inst.Deployment.Zone, inst.InstanceGroup()).Do()
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
		infof("waiting for all instances in instance group name=%s to be available", inst.InstanceGroup())
		V(retry(f, 5*time.Second, 5*time.Minute))
		infof("all instances available")
	}
}

func migrateInstances(inst Install) {
	project := inst.Deployment.Project
	zone := inst.Deployment.Zone
	name := inst.InstanceGroup()
	dc := inst.DeploymentConfig()

	waitForInstanceGroup(inst)

	igm, err := gce.InstanceGroupManagers.Get(project, zone, name).Do()
	V(err)
	groupTemplate := lastPathComponent(igm.InstanceTemplate)

	result, err := gce.InstanceGroupManagers.ListManagedInstances(project, zone, name).Do()
	V(err)

	goodInstances := []string{}
	badInstances := []string{}

	for _, instance := range result.ManagedInstances {
		instanceName := lastPathComponent(instance.Instance)
		result, err := gce.Instances.Get(project, zone, instanceName).Do()
		V(err)

		instanceTemplate := ""
		for _, item := range result.Metadata.Items {
			if item.Key == "instance-template" {
				instanceTemplate = lastPathComponent(*item.Value)
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

	if len(goodInstances) < dc.InstanceCount {
		newInstances := dc.InstanceCount - len(goodInstances)
		infof("creating new instances count=%d", newInstances)
		wait(gce.InstanceGroupManagers.Resize(project, zone, name, igm.TargetSize+int64(newInstances)).Do())
		waitForInstanceGroup(inst)
	}

	if len(badInstances) > 0 {
		infof("removing old instances count=%d", len(badInstances))
		req := &compute.InstanceGroupManagersDeleteInstancesRequest{
			Instances: badInstances,
		}
		wait(gce.InstanceGroupManagers.DeleteInstances(project, zone, name, req).Do())
		waitForInstanceGroup(inst)
	}

	// delete all templates with a version number less than the current one
	_, groupTemplateVersionRaw := RPartition(groupTemplate, "-")
	groupTemplateVersion, err := strconv.Atoi(groupTemplateVersionRaw)
	V(err)

	templates, err := gce.InstanceTemplates.List(project).Filter(fmt.Sprintf(`name eq '%s-\d+'`, inst.TemplateBase())).Do()
	V(err)
	for _, template := range templates.Items {
		_, versionRaw := RPartition(template.Name, "-")
		version, err := strconv.Atoi(versionRaw)
		V(err)
		if version < groupTemplateVersion {
			infof("deleting instance template name=%s", template.Name)
			wait(gce.InstanceTemplates.Delete(project, template.Name).Do())
		}
	}

	if igm.TargetSize != int64(dc.InstanceCount) {
		infof("resizing from %d to %d instances", igm.TargetSize, dc.InstanceCount)
		wait(gce.InstanceGroupManagers.Resize(project, zone, name, int64(dc.InstanceCount)).Do())
		waitForInstanceGroup(inst)
	}
}
