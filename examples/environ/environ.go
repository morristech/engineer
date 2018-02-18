package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/pushbullet/engineer"
)

func main() {
	fmt.Println("started")

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cats := os.Getenv("cats")
		if cats == "" {
			cats = "<unset>"
		}
		fmt.Fprintf(w, "Engineer example app!\nCurrent cats level: %+v\n", cats)
	})

	var addr string
	if engineer.Development() {
		addr = "127.0.0.1:8080"
	} else {
		addr = ":80"
	}

	server, listener, err := engineer.NewServer(addr)
	if err != nil {
		panic(err)
	}

	server.Handler = mux
	if err := engineer.ServeUntilTerminate(server, listener); err != nil {
		panic(err)
	}
}
