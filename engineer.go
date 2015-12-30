package engineer

import (
	"encoding/json"
	"log"
	"os"
	"strconv"

	"golang.org/x/net/context"
	"google.golang.org/cloud/storage"
)

func init() {
	// agent logger already adds a timestamp, so turn that off
	log.SetFlags(0)
}

type Deployment struct {
	Name    string
	Project string
	KeyPath string
	Zone    string
	Image   string
}

type App struct {
	Name             string
	Executable       string
	Worker           bool
	GracefulShutdown bool
	DeploymentConfig map[string]DeploymentConfig
	Scopes           []string
	Tags             []string
}

type DeploymentConfig struct {
	InstanceCount int
	MachineType   string
}

type State struct {
	Version int
}

func GetState(c context.Context, bucket string) (*State, error) {
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

func PutState(c context.Context, bucket string, state *State) error {
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

func Project() string {
	return os.Getenv("ENGR_PROJECT")
}

func AppName() string {
	return os.Getenv("ENGR_APP")
}

func Version() int {
	v, _ := strconv.Atoi(os.Getenv("ENGR_VERSION"))
	return v
}

func Development() bool {
	return os.Getenv("ENGR_DEVELOPMENT") == "1"
}
