package main

/*

Environment Example

1. Deploy this by adding the following to engr.json and running "engr dev environ deploy":

{
  "Deployments": {
    "dev": {
      "Project": "<project name>",
      "Zone": "us-central1-c"
    }
  },
	"Apps": {
		"environ": {
			"Executable": "engineer/examples/environ",
			"Tags": ["http-server"]
		}
	}
}

2. Find the IP address by using "engr dev environ status"
3. Run "curl http://<ip address>/"
4. Run "engr dev environ setenv cats meow"
5. Run "curl http://<ip address>/" and you should see the updated environment
6. Run "engr dev environ destroy" to remove all created resources

*/

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	fmt.Println("started")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "cats: %+v\n", os.Getenv("cats"))
	})

	if err := http.ListenAndServe(":80", nil); err != nil {
		panic(err)
	}
}
