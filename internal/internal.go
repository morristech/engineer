package internal

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/pubsub"
	"golang.org/x/net/context"
)

type StatusResult struct {
	InstanceUptime time.Duration
	AppUptime      time.Duration
	AppVersion     int
}

type Message struct {
	RequestID     string
	Published     time.Time
	Instance      string
	Command       Command
	UpdateVersion int

	StatusResult StatusResult

	Error string
}

type Command string

const (
	CommandUpdate Command = "update"
	CommandStatus         = "status"
)

func TopicFromAppName(pubsubClient *pubsub.Client, appName string) *pubsub.Topic {
	return pubsubClient.Topic(appName + "-topic")
}

func SendMessage(c context.Context, message Message, topic *pubsub.Topic) error {
	message.Published = time.Now().UTC()

	j, err := json.Marshal(message)
	if err != nil {
		return err
	}
	pm := &pubsub.Message{
		Data: []byte(j),
	}

	_, err = topic.Publish(c, pm)
	if err != nil {
		return err
	}
	return nil
}

type App struct {
	Name             string   `json:"-"`
	Package          string   `json:"package"`
	Server           bool     `json:"server"`
	Debug            bool     `json:"debug"`
	GracefulShutdown bool     `json:"graceful-shutdown"`
	Scopes           []string `json:"scopes"`
	Tags             []string `json:"tags"`
	InstanceCount    int      `json:"instance-count"`
	MachineType      string   `json:"machine-type"`
	Project          string   `json:"project"`
	Zone             string   `json:"zone"`
	Image            string   `json:"image"`
	StagedDeploy     bool     `json:"staged-deploy"`
	Generate         bool     `json:"generate"`
	Local            bool     `json:"-"`
}

func (a *App) TargetPool() string {
	return fmt.Sprintf("%s-pool", a.Name)
}

func (a *App) Address() string {
	return fmt.Sprintf("%s-address", a.Name)
}

func (a *App) ForwardingRule() string {
	return fmt.Sprintf("%s-rule", a.Name)
}

func (a *App) HealthCheck() string {
	return fmt.Sprintf("%s-check", a.Name)
}

func (a *App) InstanceGroup(version int) string {
	return fmt.Sprintf("%s-group-%d", a.Name, version)
}

func (a *App) InstanceGroupSingleton() string {
	return fmt.Sprintf("%s-group", a.Name)
}

func (a *App) Template(version int) string {
	return fmt.Sprintf("%s-template-%d", a.Name, version)
}

func (a *App) InstanceBase(version int) string {
	return fmt.Sprintf("%s-%d", a.Name, version)
}

func (a *App) InstanceBaseSingleton() string {
	return a.Name
}

func (a *App) Bucket() string {
	return fmt.Sprintf("%s-%s", a.Project, a.Name)
}

func (a *App) Region() string {
	parts := strings.Split(a.Zone, "-")
	return strings.Join(parts[:len(parts)-1], "-")
}
