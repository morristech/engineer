package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/pushbullet/engineer/internal"

	"golang.org/x/net/context"
	"google.golang.org/cloud/pubsub"
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
func PrepareRPC(c context.Context, appName string) {
	preparedRPCIDLock.Lock()
	defer preparedRPCIDLock.Unlock()
	id := randString(16)
	topic := internal.TopicFromAppName(appName)
	if err := pubsub.CreateSub(c, topic+"-"+id, topic, 10*time.Second, ""); err != nil {
		return
	}
	preparedRPCID = id
}

func RPC(c context.Context, appName string, command internal.Command, version int, count int) ([]*internal.Message, error) {
	if count == 0 {
		return nil, nil
	}

	topic := internal.TopicFromAppName(appName)

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

	sub := topic + "-" + id

	if createSubscription {
		if err := pubsub.CreateSub(c, sub, topic, 10*time.Second, ""); err != nil {
			return nil, err
		}
	}

	defer pubsub.DeleteSub(c, sub)

	req := internal.Message{
		RequestID:     id,
		Command:       command,
		UpdateVersion: version,
	}
	// sent := time.Now()
	if err := internal.SendMessage(c, appName, req); err != nil {
		return nil, err
	}

	// if I receive some messages but get a context timeout, this won't work I think
	received := 0
	replies := []*internal.Message{}
	for {
		msgs, err := pubsub.PullWait(c, sub, 1)
		if err != nil {
			return nil, err
		}

		if len(msgs) == 0 {
			// timed out
			return replies, errors.New("timeout")
		}

		msg := msgs[0]

		if err := pubsub.Ack(c, sub, msg.AckID); err != nil {
			return nil, err
		}

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
		if received == count {
			break
		}
	}
	return replies, nil
}
