package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
)

var gce *compute.Service

const (
	imageScript = `
sudo apt-get update
sudo env DEBIAN_FRONTEND=noninteractive apt-get upgrade --yes --force-yes
`
	zone = "us-central1-c"
)

func V(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("you must specify the project as the only option to this tool")
	}

	project := os.Args[1]

	client, err := google.DefaultClient(oauth2.NoContext, "https://www.googleapis.com/auth/compute")
	if err != nil {
		log.Fatal("could not find google account, make sure you have run `gcloud auth login`", err)
	}
	gce, err = compute.New(client)
	V(err)

	imageName := "engr-image-" + time.Now().Format("20060102t150405")

	baseImageURL := ""
	imageList, err := gce.Images.List("debian-cloud").Filter("name eq 'debian-8-.*'").Do()
	V(err)
	for _, image := range imageList.Items {
		if image.Deprecated != nil {
			continue
		}
		baseImageURL = image.SelfLink
		break
	}

	if baseImageURL == "" {
		V(errors.New("could not find base image"))
	}

	commands := strings.Split(strings.TrimSpace(imageScript), "\n")

	const (
		instanceName = "engr-build-image"
	)

	if resourceExists(gce.Instances.Get(project, zone, instanceName).Do()) {
		fmt.Println("deleting existing instance")
		wait(gce.Instances.Delete(project, zone, instanceName).Do())
	}

	if resourceExists(gce.Disks.Get(project, zone, instanceName).Do()) {
		fmt.Println("deleting existing disk")
		wait(gce.Disks.Delete(project, zone, instanceName).Do())
	}

	instance := &compute.Instance{
		MachineType: "zones/" + zone + "/machineTypes/n1-standard-1",
		Name:        instanceName,
		Tags:        &compute.Tags{Items: []string{"engr-builder"}},
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

	fmt.Println("creating instance", instanceName)
	wait(gce.Instances.Insert(project, zone, instance).Do())

	// make sure ssh is allowed
	const (
		firewallRule = "image-builder-ssh"
	)

	if !resourceExists(gce.Firewalls.Get(project, firewallRule).Do()) {
		fmt.Println("creating firewall rule")
		firewall := &compute.Firewall{
			Name: firewallRule,
			Allowed: []*compute.FirewallAllowed{
				&compute.FirewallAllowed{
					IPProtocol: "tcp",
					Ports:      []string{"22"},
				},
			},
			SourceRanges: []string{"0.0.0.0/0"},
			TargetTags:   []string{"engr-builder"},
		}
		wait(gce.Firewalls.Insert(project, firewall).Do())
	}

	sshclient, err := createSSHClient(project, ipForInstance(project, instanceName), 60*time.Second)
	V(err)

	for _, command := range commands {
		s, err := sshclient.NewSession()
		V(err)
		fmt.Printf("running command: %s\n", command)
		s.Stdout = os.Stdout
		s.Stderr = os.Stdout
		if err := s.Run(command); err != nil {
			log.Fatal("ssh command failed", err)
		}
		s.Close()
	}

	fmt.Println("deleting firewall rule")
	wait(gce.Firewalls.Delete(project, firewallRule).Do())

	fmt.Println("deleting instance")
	wait(gce.Instances.Delete(project, zone, instanceName).Do())

	fmt.Println("creating image")
	image := &compute.Image{
		Name:       imageName,
		SourceDisk: fmt.Sprintf("zones/%s/disks/%s", zone, instanceName),
	}
	wait(gce.Images.Insert(project, image).Do())

	fmt.Println("deleting disk")
	wait(gce.Disks.Delete(project, zone, instanceName).Do())

	fmt.Println("created image", imageName)
	fmt.Printf("set this as the image for your app with `engr <app> config:set image %s`\n", imageName)
}

func wait(originalOp *compute.Operation, err error) {
	V(err)
	project := strings.Split(originalOp.SelfLink, "/")[6]
	for {
		var op *compute.Operation
		var err error
		if originalOp.Zone != "" {
			op, err = gce.ZoneOperations.Get(project, lastPathComponent(originalOp.Zone), originalOp.Name).Do()
		} else if originalOp.Region != "" {
			op, err = gce.RegionOperations.Get(project, lastPathComponent(originalOp.Region), originalOp.Name).Do()
		} else {
			op, err = gce.GlobalOperations.Get(project, originalOp.Name).Do()
		}
		V(err)
		if op.Status == "DONE" {
			if op.Error != nil {
				for _, e := range op.Error.Errors {
					log.Fatal(e.Message)
				}
				os.Exit(1)
			}
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func createSSHClient(project string, ipAddress string, timeout time.Duration) (*ssh.Client, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	sshKeyPath := u.HomeDir + "/.ssh/engineer-" + project

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
	}

	keyBytes, err := ioutil.ReadFile(sshKeyPath)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	prj, err := gce.Projects.Get(project).Do()
	if err != nil {
		return nil, err
	}

	builderKey := "build:" + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " engineer@example.com"
	sshKeysExists := false
	for _, item := range prj.CommonInstanceMetadata.Items {
		if item.Key == "sshKeys" {
			sshKeysExists = true
			keys := strings.Split(strings.TrimSpace(*item.Value), "\n")
			found := false
			for _, key := range keys {
				if key == builderKey {
					found = true
					break
				}
			}
			if !found {
				v := strings.Join(append(keys, builderKey), "\n")
				item.Value = &v
			}
			break
		}
	}

	if !sshKeysExists {
		prj.CommonInstanceMetadata.Items = append(prj.CommonInstanceMetadata.Items, &compute.MetadataItems{Key: "sshKeys", Value: &builderKey})
	}

	wait(gce.Projects.SetCommonInstanceMetadata(project, prj.CommonInstanceMetadata).Do())

	config := &ssh.ClientConfig{
		User: "build",
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

func ipForInstance(project string, instance string) string {
	resp, err := gce.Instances.Get(project, zone, instance).Do()
	V(err)
	return resp.NetworkInterfaces[0].AccessConfigs[0].NatIP
}

func resourceExists(resp interface{}, err error) bool {
	if e, ok := err.(*googleapi.Error); ok {
		if e.Code == 404 {
			return false
		}
	}
	V(err)
	return true
}

func lastPathComponent(u string) string {
	parts := strings.Split(u, "/")
	last := parts[len(parts)-1]
	if last == "" {
		return u
	} else {
		return last
	}
}
