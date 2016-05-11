package engineer

import (
	"log"
	"os"
	"strconv"
)

func init() {
	// agent logger already adds a timestamp, so turn that off
	log.SetFlags(0)
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
