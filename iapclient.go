package iapclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/pkg/errors"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
)

const (
	iamScope      = "https://www.googleapis.com/auth/iam"
	oauthTokenURI = "https://www.googleapis.com/oauth2/v4/token"
	jwtGrantType  = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

type oAuthTokenBody struct {
	IDToken string `json:"id_token"`
}

// claimSet represents a JWT claimSet to represent all the fields for creating
// the specific JSON Web Token we need
type claimSet struct {
	Aud            string `json:"aud"`
	Exp            int64  `json:"exp"`
	Iss            string `json:"iss"`
	Iat            int64  `json:"iat"`
	TargetAudience string `json:"target_audience"`
}

// credentialJSON represents a service account JSON credentials file
type credentialJSON struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	AuthURI                 string `json:"auth_uri"`
	TokenURI                string `json:"token_uri"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CertURL       string `json:"client_x509_cert_url"`
}

type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// IAP struct to represent the latest retrieved auth details
type IAP struct {
	sync.Mutex
	clientID    string
	signerEmail string
	jwt         *claimSet
	signedJwt   string
	oidc        string
	httpClient  Doer
	context     context.Context
	Transport   http.RoundTripper
}

// Side-effect dependencies for masking in tests
var googleFindDefaultCredentials = google.FindDefaultCredentials
var metadataGet = metadata.Get
var signJwt = signJwtReal

// NewIAP creates a new IAP object to fetch and refresh IAP authentication
func NewIAP(cid string) (*IAP, error) {
	// We should only have to get this once

	iap := IAP{
		clientID:  cid,
		jwt:       &claimSet{},
		Transport: &http.Transport{},
	}
	return &iap, nil
}

// A wrapper to deal with upstream API call so we can skip this all during testing
func signJwtReal(httpClient Doer, name string, request *iam.SignJwtRequest) (string, error) {
	client, ok := httpClient.(*http.Client)
	if !ok {
		return "", fmt.Errorf("unknown client type: %T", httpClient)
	}
	svc, err := iam.New(client)
	if err != nil {
		return "", errors.Wrap(err, "failed to get IAM client")
	}
	ret, err := svc.Projects.ServiceAccounts.SignJwt(name, request).Do()
	if err != nil {
		return "", errors.Wrap(err, "failed to get JWT signed by Google")
	}
	return ret.SignedJwt, nil
}

// refreshJwt generates a JWT containing all needed info, and uses the SignJwt
// API to get a version signed by the service account in use. We do this
// instead of signing it ourselves because a) we don't have the private key in
// some cases (Application Default), and b) that requires a bunch more
// libraries
func (iap *IAP) refreshJwt() error {
	iap.jwt.Exp = time.Now().Add(time.Hour).Unix()
	iap.jwt.Aud = oauthTokenURI
	iap.jwt.Iss = iap.signerEmail
	iap.jwt.Iat = time.Now().Unix()
	iap.jwt.TargetAudience = iap.clientID

	claimSetJSON, err := json.Marshal(iap.jwt)
	if err != nil {
		return errors.Wrap(err, "failed to marshal claimset to JSON")
	}

	signJwtName := fmt.Sprintf("projects/-/serviceAccounts/%v", iap.signerEmail)
	var signJwtRequest iam.SignJwtRequest
	signJwtRequest.Payload = string(claimSetJSON)

	signedJwt, err := signJwt(iap.httpClient, signJwtName, &signJwtRequest)
	if err != nil {
		// already wrapped by signJwt
		return err
	}

	iap.signedJwt = signedJwt
	return nil
}

// refreshOIDC is responsible for using our previously gotten JWT to talk to
// the Google OAuth URI to get a OIDC bearer token. This token is the one
// actually sent to the IAP-protected endpoint as auth
func (iap *IAP) refreshOIDC() error {
	data := url.Values{}
	data.Set("assertion", iap.signedJwt)
	data.Set("grant_type", jwtGrantType)

	req, err := http.NewRequest("POST", oauthTokenURI, strings.NewReader(data.Encode()))
	if err != nil {
		return errors.Wrap(err, "failed to create HTTP request to get OAuth Token")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))

	resp, err := iap.httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "OAuth Token HTTP request failed")
	}
	defer resp.Body.Close()

	bodyJSON, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read OAuth Token HTTP response body")
	}

	var body oAuthTokenBody
	if err := json.Unmarshal(bodyJSON, &body); err != nil {
		return errors.Wrap(err, "OAuth token unmarshal failed")
	}

	iap.oidc = body.IDToken
	return nil
}

// getSignerEmail finds the service account's email address, either via the
// Default Credentials JSON blob, or via the metadata service
func (iap *IAP) getSignerEmail() error {
	credentials, err := googleFindDefaultCredentials(iap.context)
	if err != nil {
		return errors.Wrap(err, "google.FindDefaultCredentials failed")
	}

	var credJSON credentialJSON
	if err := json.Unmarshal(credentials.JSON, &credJSON); err != nil {
		return errors.Wrap(err, "failed to unmarshal Google Default Credential JSON")
	}

	if credJSON == (credentialJSON{}) {
		// Looks like we're in GCE - Use the metadata service
		signerEmail, err := metadataGet("instance/service-accounts/default/email")
		if err != nil {
			return errors.Wrap(err, "metadata get failed")
		}
		iap.signerEmail = signerEmail
	} else {
		// We're local with JSON file - Get the email directly
		if credJSON.Type != "service_account" {
			return fmt.Errorf("IAP auth only works with service_accounts, got %v", credJSON.Type)
		}
		iap.signerEmail = credJSON.ClientEmail
	}
	return nil
}

// refresh is responsible for last-minute initialization, as well as auth
// refreshing (if needed based on expiry)
func (iap *IAP) refresh(ctx context.Context) error {
	iap.Lock()
	defer iap.Unlock()

	// Use the context from the http request that triggered the refresh for the
	// ancillary requests
	iap.context = ctx

	// Initialize
	if iap.signerEmail == "" {
		if err := iap.getSignerEmail(); err != nil {
			return errors.Wrap(err, "failed to get service account email")
		}
	}

	if iap.httpClient == nil {
		httpClient, err := google.DefaultClient(iap.context, iamScope)
		if err != nil {
			return errors.Wrap(err, "google.DefaultClient failed")
		}
		iap.httpClient = httpClient
	}

	// Refresh
	if iap.jwt.Exp-10 < time.Now().Unix() {
		if err := iap.refreshJwt(); err != nil {
			return errors.Wrap(err, "failed to get and sign JWT")
		}
		if err := iap.refreshOIDC(); err != nil {
			return errors.Wrap(err, "failed to get OIDC")
		}
	}

	return nil
}

// RoundTrip makes the IAP object into a valid http.Transport interface
func (iap *IAP) RoundTrip(req *http.Request) (resp *http.Response, err error) {

	if err := iap.refresh(req.Context()); err != nil {
		return nil, errors.Wrap(err, "failed to refresh auth")
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", iap.oidc))

	resp, err = iap.Transport.RoundTrip(req)
	return resp, err
}
