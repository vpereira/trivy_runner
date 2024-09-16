package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// Dumping request method, URL, and headers
	fmt.Println("Method:", r.Method)
	fmt.Println("URL:", r.URL)
	fmt.Println("Headers:", r.Header)

	// Reading and dumping the request body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("Error reading body:", err)
	}
	fmt.Println("Body:", string(body))

	// Sending a simple response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Request received and logged"))
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Server is listening on port 8081...")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
