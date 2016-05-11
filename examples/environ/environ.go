package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/pushbullet/engineer"
)

func main() {
	fmt.Println("started")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cats := os.Getenv("cats")
		if cats == "" {
			cats = "<unset>"
		}
		fmt.Fprintf(w, "Engineer example app!\nCurrent cats level: %+v\n", cats)
	})

	if engineer.Development() {
		if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
			panic(err)
		}
	} else {
		if err := http.ListenAndServe(":80", nil); err != nil {
			panic(err)
		}
	}
}
