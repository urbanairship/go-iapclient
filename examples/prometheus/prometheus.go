package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	prometheus "github.com/prometheus/client_golang/api"
	prometheusAPI "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
	"github.com/urbanairship/go-iapclient"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	clientID = kingpin.Flag("client-id", "OAuth Client ID").Required().String()
	uri      = kingpin.Flag("uri", "Base URI of Prometheus").Required().String()
	caFile   = kingpin.Flag("ca-file", "Custom CA PEM file").Required().ExistingFile()
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
	//return &http.Transport{TLSClientConfig: tlsConfig}, nil
	return &http.Transport{TLSClientConfig: tlsConfig}, nil
}

func main() {
	kingpin.Parse()

	iap, err := iapclient.NewIAP(*clientID)
	if err != nil {
		log.Fatalf("Failed to create new IAP object: %v", err)
	}

	// customize the trusted CA list to support talking to prom
	transport, err := getCustomTransport(:
	if err != nil {
		log.Fatalf("Coudln't get custom transport: %v", err)
	}
	iap.Transport = transport

	client, err := prometheus.NewClient(prometheus.Config{Address: *uri, RoundTripper: iap})
	if err != nil {
		log.Fatalf("Failed to get prometheus client: %v", err)
	}

	api := prometheusAPI.NewAPI(client)

	val, err := api.Query(context.Background(), "ALERTS{}", time.Now())
	if err != nil {
		log.Fatalf("Failed to get some shit: %v", err)
	}
	switch {
	case val.Type() == model.ValScalar:
		scalarVal := val.(*model.Scalar)
		log.Printf("Scalar: %v", scalarVal)
	case val.Type() == model.ValVector:
		vectorVal := val.(model.Vector)
		for _, elem := range vectorVal {
			// do something with each element in the vector
			log.Printf("elem: %v -- %v\n", elem.Metric, elem.Value)
		}
	}

}
