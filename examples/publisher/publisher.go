package main

/*

Publisher Example

1. Deploy this by adding the following to engr.json and running "engr dev publisher deploy":

{
  "Deployments": {
    "dev": {
      "Project": "<project name>",
      "Zone": "us-central1-c"
    }
  },
	"Apps": {
		"publisher": {
			"Executable": "engineer/examples/publisher",
			"Scopes": ["https://www.googleapis.com/auth/pubsub"],
			"Tags": ["http-server"]
		}
	}
}

2. Find the IP address by using "engr dev publisher status"
3. Run "curl http://<ip address>/" and a new message should be published to the topic "engr-test-topic"
4. Check the cloud console logs for your project.  View the logs for "Custom Logs"
		and you should see the logs for this module whenever you make a request
5. Deploy the subscriber example to consume these messages.
6. Run "engr dev publisher destroy" to remove all created resources

*/

import (
	"engineer"
	"fmt"
	"net/http"
	"os"
	"strconv"

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

	exists, err := pubsub.TopicExists(c, topic)
	if err != nil {
		panic(err)
	}

	if !exists {
		if err := pubsub.CreateTopic(c, topic); err != nil {
			panic(err)
		}
	}

	counter := 0
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		msgIDs, err := pubsub.Publish(c, topic, &pubsub.Message{
			Data: []byte("message #" + strconv.Itoa(counter)),
		})
		counter++
		if err == nil {
			fmt.Printf("published counter=%d id=%s\n", counter, msgIDs[0])
		} else {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, "err=%v\n", err)
		}
	})

	if err := engineer.ListenAndServe(":80", nil); err != nil {
		panic(err)
	}
}
