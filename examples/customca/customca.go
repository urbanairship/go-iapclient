package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/urbanairship/go-iapclient"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	cid    = kingpin.Flag("client-id", "OAuth Client ID").Required().String()
	uri    = kingpin.Flag("uri", "URI to get").Required().String()
	caFile = kingpin.Flag("ca-file", "Custom CA PEM file").Required().ExistingFile()
)

func getCustomTransport() (transport *http.Transport, err error) {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	pemData, err := ioutil.ReadFile(*caFile)
	if err != nil {
		return nil, err
	}

	ok := rootCAs.AppendCertsFromPEM(pemData)
	if !ok {
		return nil, err
	}

	tlsConfig := &tls.Config{RootCAs: rootCAs}
	return &http.Transport{TLSClientConfig: tlsConfig}, nil
}

func main() {
	kingpin.Parse()

	req, err := http.NewRequest("GET", *uri, nil)
	if err != nil {
		log.Fatalf("Failed create HTTP request: %v", err)
	}

	iap, err := iapclient.NewIAP(*cid)
	if err != nil {
		log.Fatalf("Failed to create new IAP object: %v", err)
	}

	// customize the trusted CA list to support talking to prom
	transport, err := getCustomTransport()
	if err != nil {
		log.Fatalf("Couldn't get custom transport: %v", err)
	}
	iap.Transport = transport

	httpClient := &http.Client{Transport: iap}

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
