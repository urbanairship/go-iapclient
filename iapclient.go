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

// ClaimSet represents a JWT ClaimSet to represent all the fields for creating
// the specific JSON Web Token we need
type ClaimSet struct {
	Aud            string `json:"aud"`
	Exp            int64  `json:"exp"`
	Scope          string `json:"scope"`
	Iss            string `json:"iss"`
	Iat            int64  `json:"iat"`
	Typ            string `json:"typ,omitempty"`
	Sub            string `json:"sub,omitempty"`
	TargetAudience string `json:"target_audience"`
}

// CredentialJSON represents a service account JSON credentials file
type CredentialJSON struct {
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
	ClientID     string
	SignerEmail  string
	Jwt          *ClaimSet
	SignedJwt    string
	OIDC         string
	Transport    *http.Transport
	GoogleClient *http.Client
}

var refreshLock sync.Mutex

// NewIAP creates a new IAP object to fetch and refresh IAP authentication
func NewIAP(clientID string) (*IAP, error) {
	// We should only have to get this once

	iap := IAP{
		ClientID:  clientID,
		Jwt:       &ClaimSet{},
		Transport: &http.Transport{},
	}
	return &iap, nil
}

func (iap *IAP) refreshJwt(ctx context.Context) error {
	signJwtName := fmt.Sprintf("projects/-/serviceAccounts/%v", iap.SignerEmail)

	iap.Jwt.Exp = time.Now().Add(time.Hour).Unix()
	iap.Jwt.Aud = oauthTokenURI
	iap.Jwt.Iss = iap.SignerEmail
	iap.Jwt.Iat = time.Now().Unix()
	iap.Jwt.TargetAudience = iap.ClientID

	claimSetJSON, err := json.Marshal(iap.Jwt)
	if err != nil {
		return errors.Wrap(err, "failed to marshal claimset to JSON")
	}

	var signJwtRequest iam.SignJwtRequest
	signJwtRequest.Payload = string(claimSetJSON)

	svc, err := iam.New(iap.GoogleClient)
	if err != nil {
		return errors.Wrap(err, "failed to get IAM client")
	}

	ret, err := svc.Projects.ServiceAccounts.SignJwt(signJwtName, &signJwtRequest).Do()
	if err != nil {
		return errors.Wrap(err, "failed to get JWT signed by Google")
	}

	iap.SignedJwt = ret.SignedJwt

	return nil
}

func (iap *IAP) refreshOIDC(ctx context.Context) error {
	data := url.Values{}
	data.Set("assertion", iap.SignedJwt)
	data.Set("grant_type", jwtGrantType)

	tokenReq, err := http.NewRequest("POST", oauthTokenURI, strings.NewReader(data.Encode()))
	if err != nil {
		return errors.Wrap(err, "failed to create HTTP request to get OAuth Token")
	}

	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))

	tokenResp, err := iap.GoogleClient.Do(tokenReq)
	if err != nil {
		return errors.Wrap(err, "OAuth Token HTTP request failed")
	}

	bodyJSON, err := ioutil.ReadAll(tokenResp.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read OAuth Token HTTP response body")
	}

	var body oAuthTokenBody
	if err := json.Unmarshal(bodyJSON, &body); err != nil {
		return errors.Wrap(err, "failed to unmarshal OAuth Token HTTP response body JSON")
	}
	iap.OIDC = body.IDToken
	return nil
}

func (iap *IAP) refresh(ctx context.Context) error {
	refreshLock.Lock()
	defer refreshLock.Unlock()

	if iap.GoogleClient == nil {
		httpClient, err := google.DefaultClient(ctx, iamScope)
		if err != nil {
			return errors.Wrap(err, "failed to get Google Default Client")
		}
		iap.GoogleClient = httpClient
	}

	if iap.SignerEmail == "" {
		credentials, err := google.FindDefaultCredentials(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to get Google Default Credentials")
		}

		var credentialJSON CredentialJSON
		if err := json.Unmarshal(credentials.JSON, &credentialJSON); err != nil {
			return errors.Wrap(err, "failed to unmarshal Google Default Credential JSON")
		}

		if credentialJSON == (CredentialJSON{}) {
			// Looks like we're in GCE - Use the metadata service
			signerEmail, err := metadata.Get("instance/service-accounts/default/email")
			if err != nil {
				return errors.Wrap(err, "failed to get service account email from metadata server")
			}
			iap.SignerEmail = signerEmail
		} else {
			// We're local with JSON file
			if credentialJSON.Type != "service_account" {
				return fmt.Errorf("iapclient: IAP auth only works with service_accounts, not %v", credentialJSON.Type)
			}
			iap.SignerEmail = credentialJSON.ClientEmail
		}
	}

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

// RoundTrip makes the IAP object into a valid http.Transport interface
func (iap *IAP) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	if err := iap.refresh(req.Context()); err != nil {
		return nil, errors.Wrap(err, "failed to refresh auth")
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", iap.OIDC))

	resp, err = iap.Transport.RoundTrip(req)
	return resp, err
}
