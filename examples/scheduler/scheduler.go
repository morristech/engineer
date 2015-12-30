package main

/*

Scheduler Example

1. Deploy this by adding the following to engr.json and running "engr dev scheduler deploy":

{
  "Deployments": {
    "dev": {
      "Project": "<project name>",
      "Zone": "us-central1-c"
    }
  },
	"Apps": {
		"scheduler": {
			"Executable": "github.com/pushbullet/engineer/examples/scheduler",
      "Scopes": ["https://www.googleapis.com/auth/pubsub"],
			"Worker": true
		}
	}
}

2. View the logs with "engr dev scheduler logs" and you should see the logs for this app as it publishes a new message every 5 seconds
3. Run "engr dev scheduler destroy" to remove all created resources

*/

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/pushbullet/engineer"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/cloud"
	"google.golang.org/cloud/pubsub"
)

const (
	topic = "scheduler"
)

type Payload struct {
	ID            string
	Name          string
	Time          time.Time
	PublishedTime time.Time
}

type Entry struct {
	Name   string
	Start  time.Time
	Period time.Duration
}

var entries = []Entry{
	{
		Name:   "backup-db",
		Start:  MustParse("2000-01-01T00:00:00Z"),
		Period: 5 * time.Second,
	},
}

func MustParse(value string) time.Time {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(`scheduler: Parse("` + value + `"): ` + err.Error())
	}
	return t
}

func main() {
	c := context.Background()
	client, err := google.DefaultClient(c, "https://www.googleapis.com/auth/pubsub")
	if err != nil {
		panic(err)
	}
	c = cloud.WithContext(c, engineer.Project(), client)

	fmt.Println("started")

	exists, err := pubsub.TopicExists(c, topic)
	if err != nil {
		panic(err)
	}

	if !exists {
		if err := pubsub.CreateTopic(c, topic); err != nil {
			panic(err)
		}
	}

	var lastNow time.Time
	now := time.Now().UTC().Truncate(time.Second)

	for {
		// advance to the next second
		lastNow = now
		now = now.Add(time.Second)

		// need to wait for now to come to pass, should be a maximum wait of 1 second
		duration := now.Sub(time.Now())
		time.Sleep(duration)

		// find any entries that should have happened in the last second
		for _, entry := range entries {
			if entry.Period < time.Second {
				fmt.Fprintf(os.Stderr, "period too short for entry name=%s\n", entry.Name)
				continue
			}

			lastRepetition := int64(lastNow.Sub(entry.Start) / entry.Period)
			currentRepetition := int64(now.Sub(entry.Start) / entry.Period)
			if currentRepetition > lastRepetition {
				payload := Payload{
					Name:          entry.Name,
					Time:          now,
					PublishedTime: time.Now().UTC(),
				}

				jsonPayload, err := json.Marshal(payload)
				if err != nil {
					panic(err)
				}

				delay := 1 * time.Second
				for {
					_, err = pubsub.Publish(c, topic, &pubsub.Message{
						Data: jsonPayload,
					})
					if err == nil {
						break
					}
					fmt.Fprintf(os.Stderr, "failed to publish name=%s now=%v err=%v delay=%v\n", entry.Name, now, err, delay.String())
					time.Sleep(delay)
					delay *= 2
					if delay > time.Minute {
						delay = time.Minute
					}
				}
				fmt.Printf("published name=%s now=%v\n", entry.Name, now)
			}
		}
	}
}
