package main

import (
	"fmt"
	"log"

	"github.com/pushbullet/engineer"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/cloud"
	"google.golang.org/cloud/storage"
)

func main() {
	c := context.Background()

	client, err := google.DefaultClient(c, "https://www.googleapis.com/auth/devstorage.read_only")
	if err != nil {
		panic(err)
	}

	c = cloud.WithContext(c, engineer.Project(), client)

	storageClient, err := storage.NewClient(c)
	if err != nil {
		panic(err)
	}

	bucketName := engineer.Project() + "-dev-" + engineer.AppName()
	fmt.Println("bucket:", bucketName)

	var query *storage.Query
	for {
		objects, err := storageClient.Bucket(bucketName).List(c, query)
		if err != nil {
			log.Fatal(err)
		}
		for _, obj := range objects.Results {
			fmt.Printf("object name: %s, size: %v\n", obj.Name, obj.Size)
		}
		query = objects.Next
		if query == nil {
			break
		}
	}
}
