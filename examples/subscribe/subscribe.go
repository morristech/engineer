package main

import (
	"log"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/pushbullet/engineer"
	"golang.org/x/net/context"
	"google.golang.org/api/iterator"
)

const (
	topicID = "test-topic"
	subID   = "test-sub"
)

func main() {
	c := context.Background()

	pubsubClient, err := pubsub.NewClient(c, engineer.Project())
	if err != nil {
		log.Fatal(err)
	}

	topic := pubsubClient.Topic(topicID)

	sub := pubsubClient.Subscription(subID)

	exists, err := sub.Exists(c)
	if err != nil {
		log.Fatal(err)
	}

	if !exists {
		if _, err := pubsubClient.CreateSubscription(c, subID, topic, 0, nil); err != nil {
			log.Fatal(err)
		}
	}

	it, err := sub.Pull(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer it.Stop()

	go func() {
		for {
			log.Println("loop")
			time.Sleep(time.Minute)
		}
	}()

	for {
		log.Print("poll")
		msg, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("got msg=%s", msg.Data)

		msg.Done(true)

		time.Sleep(1 * time.Second)
	}
}
