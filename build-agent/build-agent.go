package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cmd := exec.Command("go", "install", "github.com/pushbullet/engineer/agent")
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "GOOS=linux", "GOARCH=amd64")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("output:", string(output))
		return err
	}

	binary, err := ioutil.ReadFile("bin/linux_amd64/agent")
	if err != nil {
		return err
	}

	{
		f, err := os.Create("src/github.com/pushbullet/engineer/engr/agent-version.go")
		if err != nil {
			return err
		}

		h := sha256.New()
		h.Write(binary)
		fmt.Fprintf(f, "package main\n\n")
		version := hex.EncodeToString(h.Sum(nil))[:8]
		fmt.Fprintf(f, "var agentVersion = \"%s\"\n", version)
		f.Close()
	}

	{
		f, err := os.Create("src/github.com/pushbullet/engineer/resources/agent")
		if err != nil {
			return err
		}
		f.Write(binary)
		f.Close()
	}

	return nil
}
