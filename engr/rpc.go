package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/pushbullet/engineer/internal"
	"golang.org/x/net/context"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

var preparedRPCID string
var preparedRPCIDLock sync.Mutex

func randString(n int) string {
	const (
		alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	)
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		r, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			panic(fmt.Errorf("api: rand error: err=%v", err))
		}
		b[i] = alphabet[int(r.Int64())]
	}
	return string(b)
}

// create a pubsub subscription in advance, to reduce latency during RPCs
// creating the subscription can take multiple seconds, deleting it seems to take less than a second
func PrepareRPC(c context.Context, appName string, pubsubClient *pubsub.Client) {
	preparedRPCIDLock.Lock()
	defer preparedRPCIDLock.Unlock()
	id := randString(16)
	topic := internal.TopicFromAppName(pubsubClient, appName)
	if _, err := pubsubClient.CreateSubscription(c, topic.ID()+"-"+id, topic, 10*time.Second, nil); err != nil {
		return
	}
	preparedRPCID = id
}

func RPC(c context.Context, appName string, command internal.Command, version int, count int, pubsubClient *pubsub.Client) ([]*internal.Message, error) {
	if count == 0 {
		return nil, nil
	}

	// if we have a prepared rpc id ready, use it
	preparedRPCIDLock.Lock()
	id := preparedRPCID
	preparedRPCID = ""
	preparedRPCIDLock.Unlock()

	createSubscription := false
	if id == "" {
		id = randString(16)
		createSubscription = true
	}

	// test program for subscriptions https://gist.github.com/christopherhesse/b4b7cb81cc738e224955b286047dd7cc
	topic := internal.TopicFromAppName(pubsubClient, appName)
	sub := pubsubClient.Subscription(topic.ID() + "-" + id)

	if createSubscription {
		if _, err := pubsubClient.CreateSubscription(c, sub.ID(), topic, 10*time.Second, nil); err != nil {
			return nil, err
		}
	}

	defer sub.Delete(c)

	req := internal.Message{
		RequestID:     id,
		Command:       command,
		UpdateVersion: version,
	}
	// sent := time.Now()
	if err := internal.SendMessage(c, req, topic); err != nil {
		return nil, err
	}

	received := 0
	replies := []*internal.Message{}

	it, err := sub.Pull(c)
	if err != nil {
		return nil, err
	}
	defer it.Stop()

	for received < count {
		msg, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if grpc.Code(err) == codes.DeadlineExceeded {
				return nil, context.DeadlineExceeded
			}
			return nil, err
		}

		msg.Done(true)

		reply := internal.Message{}
		if err := json.Unmarshal(msg.Data, &reply); err != nil {
			return nil, err
		}

		if reply.Command != "" || reply.RequestID != id {
			// ignore the request and any other messages that occur on the topic
			continue
		}
		// fmt.Printf("rpc latency=%0.2fs\n", time.Now().Sub(sent).Seconds())
		replies = append(replies, &reply)
		received++
	}

	return replies, nil
}
