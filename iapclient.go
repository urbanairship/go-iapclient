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
	Scope          string `json:"scope"`
	Iss            string `json:"iss"`
	Iat            int64  `json:"iat"`
	Typ            string `json:"typ,omitempty"`
	Sub            string `json:"sub,omitempty"`
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

// IAP struct to represent the latest retrieved auth details
type IAP struct {
	ClientID    string
	SignerEmail string
	Jwt         *claimSet
	SignedJwt   string
	OIDC        string
	Transport   http.RoundTripper
}

var refreshLock sync.Mutex

// Side-effect dependencies for masking in tests
var googleFindDefaultCredentials = google.FindDefaultCredentials
var metadataGet = metadata.Get
var signJwt = signJwtReal
var getOAuthToken = getOAuthTokenReal

// NewIAP creates a new IAP object to fetch and refresh IAP authentication
func NewIAP(clientID string) (*IAP, error) {
	// We should only have to get this once

	iap := IAP{
		ClientID:  clientID,
		Jwt:       &claimSet{},
		Transport: &http.Transport{},
	}
	return &iap, nil
}

// A wrapper to deal with upstream API call so we can skip this all during testing
func signJwtReal(ctx context.Context, name string, request *iam.SignJwtRequest) (string, error) {
	httpClient, err := google.DefaultClient(ctx, iamScope)
	if err != nil {
		return "", errors.Wrap(err, "google.DefaultClient failed")
	}
	svc, err := iam.New(httpClient)
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
func (iap *IAP) refreshJwt(ctx context.Context) error {
	iap.Jwt.Exp = time.Now().Add(time.Hour).Unix()
	iap.Jwt.Aud = oauthTokenURI
	iap.Jwt.Iss = iap.SignerEmail
	iap.Jwt.Iat = time.Now().Unix()
	iap.Jwt.TargetAudience = iap.ClientID

	claimSetJSON, err := json.Marshal(iap.Jwt)
	if err != nil {
		return errors.Wrap(err, "failed to marshal claimset to JSON")
	}

	signJwtName := fmt.Sprintf("projects/-/serviceAccounts/%v", iap.SignerEmail)
	var signJwtRequest iam.SignJwtRequest
	signJwtRequest.Payload = string(claimSetJSON)

	signedJwt, err := signJwt(ctx, signJwtName, &signJwtRequest)
	if err != nil {
		// already wrapped by signJwt
		return err
	}

	iap.SignedJwt = signedJwt
	return nil
}

func getOAuthTokenReal(ctx context.Context, assertion string) (string, error) {
	data := url.Values{}
	data.Set("assertion", assertion)
	data.Set("grant_type", jwtGrantType)

	req, err := http.NewRequest("POST", oauthTokenURI, strings.NewReader(data.Encode()))
	if err != nil {
		return "", errors.Wrap(err, "failed to create HTTP request to get OAuth Token")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))

	httpClient, err := google.DefaultClient(ctx, iamScope)
	if err != nil {
		return "", errors.Wrap(err, "google.DefaultClient failed")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "OAuth Token HTTP request failed")
	}
	defer resp.Body.Close()

	bodyJSON, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "failed to read OAuth Token HTTP response body")
	}

	var body oAuthTokenBody
	if err := json.Unmarshal(bodyJSON, &body); err != nil {
		return "", errors.Wrap(err, "OAuth token unmarshal failed")
	}

	return body.IDToken, nil
}

// refreshOIDC is responsible for using our previously gotten JWT to talk to
// the Google OAuth URI to get a OIDC bearer token. This token is the one
// actually sent to the IAP-protected endpoint as auth
func (iap *IAP) refreshOIDC(ctx context.Context) error {
	token, err := getOAuthToken(ctx, iap.SignedJwt)
	if err != nil {
		// already wrapped by getOAuthToken
		return err
	}
	iap.OIDC = token
	return nil
}

// getSignerEmail finds the service account's email address, either via the
// Default Credentials JSON blob, or via the metadata service
func (iap *IAP) getSignerEmail(ctx context.Context) error {
	if iap.SignerEmail != "" {
		return nil
	}

	credentials, err := googleFindDefaultCredentials(ctx)
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
		iap.SignerEmail = signerEmail
	} else {
		// We're local with JSON file - Get the email directly
		if credJSON.Type != "service_account" {
			return fmt.Errorf("IAP auth only works with service_accounts, got %v", credJSON.Type)
		}
		iap.SignerEmail = credJSON.ClientEmail
	}
	return nil
}

// refresh is responsible for last-minute initialization, as well as auth
// refreshing (if needed based on expiry)
func (iap *IAP) refresh(ctx context.Context) error {
	refreshLock.Lock()
	defer refreshLock.Unlock()

	// Initialize
	if err := iap.getSignerEmail(ctx); err != nil {
		return errors.Wrap(err, "failed to get service account email")
	}

	// Refresh
	if iap.Jwt.Exp-10 < time.Now().Unix() {
		if err := iap.refreshJwt(ctx); err != nil {
			return errors.Wrap(err, "failed to get and sign JWT")
		}
		if err := iap.refreshOIDC(ctx); err != nil {
			return errors.Wrap(err, "failed to get OIDC")
		}
	}

	return nil
}

// GetToken gets or refreshes and returns an IAP bearer token
func (iap *IAP) GetToken(ctx context.Context) (token string, err error) {
	if err := iap.refresh(ctx); err != nil {
		return "", errors.Wrap(err, "failed to refresh auth")
	}
	return iap.OIDC, nil
}

// RoundTrip makes the IAP object into a valid http.Transport interface
func (iap *IAP) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	if err := iap.refresh(req.Context()); err != nil {
		return nil, errors.Wrap(err, "failed to refresh auth")
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", iap.OIDC))

	resp, err = iap.Transport.RoundTrip(req)
	return resp, err
}
