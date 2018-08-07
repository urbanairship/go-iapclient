# iapclient

iapclient is a library to facilitate programmatic service-account
authentication to endpoints protected by Google Cloud Platform's Identity Aware
Proxy

See the `./examples` directory for how to use this.

In summary, iapclient.NewIAP returns an http.RoundTripper that can be set as
your http.Client's transport:
```
iap, err := iapclient.NewIAP("client-id")
if err != nil {
    log.Fatalf("Failed to create new IAP object: %v", err)
}

httpClient := &http.Client{
    Transport: iap,
}

req, err := http.NewRequest("GET", "some uri", nil)
...

```

# Why

IAP-protected resources use a weird OAuth flow that's extremely fluid for
web-browser based human clients, but quite awkward to auth to as a service
account.

The upstream documentation for this process is [Authentication Howto][1],
specifically the 'Authenticating from a service account' section.

# What this library does

The high-level summary is

1. Set permissions "appropriately"
   - roles/iam.serviceAccountTokenCreator on the Service Account's own project
   - roles/iap.httpsResourceAccessor on the target project where the
     IAP-protected resource is
1. Collect the target URI and Client ID
1. Create a custom JWT with fields
   - `exp` - Epoch time 1 hour in the future
   - `aud` - `https://www.googleapis.com/oauth2/v4/token`
   - `iss` - Service Account email (get from JSON or metadata service)
   - `iat` - Current epoch time
   - `target_audience` - IAP OAuth ClientID (must be gotten manually)
1. Use the [projects.serviceAccounts.signJwt][2] method to have Google sign the
   JWT as your service account. This is done instead of using the private key
   because Application Default auth does not have the private key unless a JSON
   file is in use, and implementing both seemed silly.
1. Do a POST to the OAuth Token URI (`https://www.googleapis.com/oauth2/v4/token`)
   Body should have the following fields:
   - `assertion` - the signed JWT gotten back from `signJwt`
   - `grant_type` - `urn:ietf:params:oauth:grant-type:jwt-bearer`
1. Use the returned string for auth by adding `Authorization: Bearer <string>`
   to the IAP-directed request

__[1] https://cloud.google.com/iap/docs/authentication-howto
[2] https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signJwt
