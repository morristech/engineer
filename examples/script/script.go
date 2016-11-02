package main

import (
	"fmt"
	"log"

	"cloud.google.com/go/storage"
	"github.com/pushbullet/engineer"
	"golang.org/x/net/context"
	"google.golang.org/api/iterator"
)

func main() {
	c := context.Background()
	storageClient, err := storage.NewClient(c)
	if err != nil {
		panic(err)
	}

	bucketName := engineer.Project() + "-" + engineer.AppName()
	fmt.Println("bucket:", bucketName)

	var query *storage.Query

	iter := storageClient.Bucket(bucketName).Objects(c, query)
	for {
		obj, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("object name: %s, size: %v\n", obj.Name, obj.Size)
	}
}
