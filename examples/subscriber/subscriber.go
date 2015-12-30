package main

/*

Subscriber Example

1. Deploy this by adding the following to engr.json and running "engr dev subscriber deploy":

{
  "Deployments": {
    "dev": {
      "Project": "<project name>",
      "Zone": "us-central1-c"
    }
  },
	"Apps": {
		"subscriber": {
			"Executable": "engineer/examples/subscriber",
			"Scopes": ["https://www.googleapis.com/auth/pubsub"],
			"Worker": true
		}
	}
}

2. Deploy the publisher module to create messages.
3. Run "curl http://<ip address>/" with the ip address of the publisher module
3. Check the cloud console logs for your project.  View the logs for "Custom Logs"
		and you should see the logs for this module whenever it receives a published message
4. Run "engr dev subscriber destroy" to remove all created resources

*/

import (
	"engineer"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"

	"google.golang.org/cloud"
	"google.golang.org/cloud/pubsub"
)

func main() {
	c := context.Background()
	client, err := google.DefaultClient(c, "https://www.googleapis.com/auth/pubsub")
	if err != nil {
		panic(err)
	}
	c = cloud.WithContext(c, engineer.Project(), client)

	fmt.Println("started")

	topic := "engr-test-topic"
	sub := "engr-test-subscription"

	exists, err := pubsub.SubExists(c, sub)
	if err != nil {
		panic(err)
	}

	if !exists {
		if err := pubsub.CreateSub(c, sub, topic, 0, ""); err != nil {
			panic(err)
		}
	}

	// if we get a SIGTERM, stop processing new messages
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGTERM)

Loop:
	for {
		fmt.Println("poll")
		msgs, err := pubsub.PullWait(c, sub, 10)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to pull err=%v\n", err)
		}
		for _, msg := range msgs {
			fmt.Printf("got msg=%+v\n", msg)
			if err := pubsub.Ack(c, sub, msg.AckID); err != nil {
				fmt.Fprintf(os.Stderr, "failed to ack message err=%v\n", err)
			} else {
				fmt.Println("acked message")
			}
		}

		select {
		case <-shutdown:
			// this won't actually work almost all of the time because poll has a timeout of 90 seconds and we only get 60 seconds to shutdown
			// ideally we could change the timeout on pubsub.PullWait() but it's not clear how to do that
			fmt.Println("shutting down")
			break Loop
		default:
			// carry on
		}

		time.Sleep(1 * time.Second)
	}
}
