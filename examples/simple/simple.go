package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/urbanairship/go-iapclient"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	cid = kingpin.Flag("client-id", "OAuth Client ID").Required().String()
	uri = kingpin.Flag("uri", "URI to get").Required().String()
)

func main() {
	kingpin.Parse()
	iap, err := iapclient.NewIAP(*cid, nil)
	if err != nil {
		log.Fatalf("Failed to create new IAP object: %v", err)
	}

	httpClient := &http.Client{
		Transport: iap,
	}

	req, err := http.NewRequest("GET", *uri, nil)
	if err != nil {
		log.Fatalf("Failed create HTTP request: %v", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("HTTP request failed: %v", err)
	}

	respBody, _ := ioutil.ReadAll(resp.Body)
	msg := fmt.Sprintf("HTTP Request: %v\n%v", resp.Status, string(respBody))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("Successful %v", msg)
	} else {
		log.Fatalf("Failed %v", msg)
	}
}
