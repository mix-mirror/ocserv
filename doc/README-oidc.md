# Using ocserv with OpenID Connect authentication

OpenID Connect (OIDC) is an identity layer built on top of the OAuth 2.0 protocol.

ocserv supports two ways of authenticating a user against an OIDC provider,
selected with the 'mode' suboption: the bearer token mode, the default, and
the browser login through the authorization code flow, with `mode=browser`.
A server serves one or the other, so that the administrator decides which
kind of client is accepted:

```
auth = "oidc[config=/etc/ocserv/oidc.json]"               # bearer tokens
auth = "oidc[config=/etc/ocserv/oidc.json,mode=browser]"  # browser login
```

Only one OIDC method can be configured on a virtual host, whether in 'auth'
or in 'enable-auth'. A virtual host without an 'auth' of its own inherits the
bearer token mode from the default one, but not `mode=browser`: its
`redirect_uri` leads back to the host it is configured for, so each virtual
host offering the browser login needs an 'auth' and a config file of its own.

OIDC support needs GnuTLS 3.8.2 or later.

## Bearer token mode

The client obtains a token from the provider on its own and presents it to
ocserv, which only validates it:

     +--------+                               +---------------+
     |        |--(A)- Authorization Request ->|   Resource    |
     |        |                               |     Owner     |
     |        |<-(B)-- Authorization Grant ---|   (end user)  |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(C)-- Authorization Grant -->| Authorization |
     | Client |                               |     Server    |
     |        |<-(D)----- Access Token -------|(oidc provider)|
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(E)----- Access Token ------>|    Resource   |
     |        |                               |     Server    |
     |        |<-(F)--- Protected Resource ---|    (ocserv)   |
     +--------+                               +---------------+

This requires a client which knows how to talk to the provider; steps (A)
through (D) happen without ocserv's involvement.

This is the default mode, `mode=bearer`. What ocserv accepts in it is
constrained by 'required_claims' alone, see below. The browser login is not
offered: a client announcing it is asked for a bearer token, and the URLs of
the browser login do not exist.

## Authorization code flow

Most VPN clients cannot obtain a token themselves, but they can open a
browser window and let the user log in there. With `mode=browser` ocserv
acts as the OpenID Connect relying party and performs the whole exchange:

     +--------+                               +---------------+
     |        |--(A)---- login request ------>|               |
     | Client |                               |    ocserv     |
     |        |<-(B)-- authorization request --|               |
     +--------+                               +---------------+
         |                                          |
         | (C) user logs in                         |
         v                                          |
     +---------------+                              |
     | Authorization |                              |
     |     Server    |--(D)-- authorization code --->|
     |(oidc provider)|<-(E)---- code + verifier -----|
     |               |--(F)-------- tokens --------->|
     +---------------+                              |
                                                    |
     +--------+                                     |
     | Client |<-(G)------ session cookie ----------+
     +--------+

ocserv generates the state, the PKCE verifier (RFC 7636) and the nonce when
it answers the login request and keeps them in the security module; only the
state leaves it, as part of the authorization request. The identity is
established inside ocserv when the code is exchanged; the client only
receives an opaque token which it presents to claim the session.

The state only identifies the request; it does not claim the session. The
token which does is generated when the code is exchanged and handed only to
the browser which completed the login: in a cookie for an embedded browser,
encrypted to the client's key for an external one. Knowing the state, which
is part of the authorization request and travels through the provider, is
therefore not enough to claim a session, and a state is only accepted by one
callback.

In terms of ocserv's processes and their IPC:

```mermaid
sequenceDiagram
    participant c as client
    participant b as browser
    participant w as worker
    participant sm as sec-mod
    participant idp as identity provider

    Note over w: auth state: PS_AUTH_INACTIVE
    c->>w: POST / (single-sign-on-v2)
    w->>sm: SEC_OIDC_START
    Note right of sm: generates state, PKCE verifier and nonce
    sm->>w: SEC_OIDC_START_REPLY
    w->>c: sso-v2 form carrying the authorization request

    c->>b: open the authorization request
    b->>idp: authorization request
    Note over b,idp: user logs in
    idp->>b: redirect with the code
    b->>w: GET the redirect URI

    w->>sm: SEC_OIDC_FINISH
    Note right of sm: takes the request, whatever the outcome
    sm->>idp: token request
    Note right of sm: blocking, bounded by a fixed timeout
    idp->>sm: tokens
    Note right of sm: validates the token and records the identity under a fresh token
    sm->>w: SEC_OIDC_FINISH_REPLY
    w->>b: the token in a cookie, redirect to the final page

    b->>c: the cookie carries the token
    c->>w: POST / (sso-token)
    w->>sm: SEC_AUTH_INIT
    Note right of sm: takes the identity recorded under the token
    sm->>w: SEC_AUTH_REP
    Note over w: auth state: PS_AUTH_COMPLETED
```

For a more detailed explanation see the OpenID Connect protocol
(<https://openid.net/connect/>).

## Supported clients

OIDC authentication in ocserv originated as an extension used by the
Microsoft Intune VPN client. That protocol is not part of the OpenConnect
protocol and is defined and maintained by Microsoft; ocserv's bearer token
mode exists to interoperate with those clients.

Bearer token mode is supported by the Microsoft Intune VPN client.

The authorization code flow is supported by clients which implement the
Cisco AnyConnect "sso-v2" protocol, such as the AnyConnect / Secure Client
family. The desktop clients use the external browser mode described below:
they hand the login page to the system browser, so a session the user
already has with the provider is reused. The mobile clients, on iOS and
Android, render it in a window of their own, the user logs in each time,
and the result comes back through a cookie.

Such clients announce the `single-sign-on-v2` capability in their initial
request, and with `mode=browser` ocserv serves them the browser login form.
A bearer token is not accepted in that mode, and a client which presents
one, as the Intune client does, is refused whatever it announces; with the
default mode, the capability is ignored and the client is asked for a bearer
token, as before.

Two cases are worth mentioning. The openconnect command line client has no
embedded browser, but implements the external browser mode described below.
The AnyConnect Universal Windows Platform client, distributed through the
Microsoft Store, announces no capabilities at all and is served the bearer
token mode instead.

## External browser

Clients which announce the `single-sign-on-external-browser` capability open
a browser of their own rather than an embedded one, and listen for the
result on a local port. This is how the openconnect command line client
performs a browser login, and it also lets the user reuse a session they
already have with the provider, which an embedded browser cannot see.

The desktop Cisco clients use this mode as well, which is why they open the
system browser. The mobile ones, on iOS and Android, announce the capability
too but do not listen for the token, so ocserv keeps them on the embedded
browser.

The token is encrypted to the key the client sends in
`X-AnyConnect-STRAP-DH-Pubkey`, using `gnutls_privkey_derive_secret()`, which
is why OIDC support needs GnuTLS 3.8.2 or later.

## Deploying OIDC authentication

An administrator wanting to deploy OIDC as an authentication scheme must do
the following:

1) Register an application identity with the OIDC provider
2) Obtain the OpenID Connect metadata document endpoint for their OIDC provider
3) Determine what claims the OIDC provider supports
4) Author a JSON document to tell ocserv how to validate the token
5) Add a line to the ocserv config file pointing to oidc config file: `auth = "oidc[config=<path to config file>]"`, with `mode=browser` added for the authorization code flow

For the authorization code flow the registered application must also allow
the redirect URI described below.

See your OIDC provider's documentation to better understand what claims they
support.

## OIDC JSON Config file

Oidc.json file format:
```json
{
    "openid_configuration_url": "<uri of openid-configuration doc>",
    "user_name_claim": "preferred_username",
    "required_claims": {
       "aud": "SomeAudience",
       "iss": "SomeIssuer"
    },
    "client_id": "<the application identity registered with the provider>",
    "client_secret": "<the application secret, if the client is confidential>",
    "redirect_uri": "https://vpn.example.com/sso/callback",
    "groups_claim": "groups",
    "sso_login_timeout": 600
}
```

Example openid-configuration doc URIs are:
1) <https://accounts.google.com/.well-known/openid-configuration>
2) <https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration>

The 'required_claims' field controls which claims must be present in a token
to permit access, in either mode. Each is compared with the token as a whole,
so an 'aud' listed here only matches a token whose audience is exactly that
value.

In the bearer token mode these are the only checks of who issued a token and
to whom: the client obtained it on its own, and without them ocserv would
accept a token the provider issued to any other application. In that mode
'required_claims' must therefore name both 'iss' and 'aud'.

With `mode=browser` the token is obtained by ocserv itself, and it is checked
further, as OpenID Connect requires: 'iss' must equal the issuer named in the
provider's metadata document, 'aud' must contain 'client_id', a token naming
other audiences as well must carry an 'azp' claim, and 'azp', when present,
must be the 'client_id'. As the issuer is compared exactly, the provider must be
reached at the address it announces as its issuer; with Keycloak behind a
proxy, set its hostname accordingly.

The remaining fields are only used with `mode=browser`; 'client_id' and
'redirect_uri' are required there, and ocserv does not start without them:

|Field|Notes|
|--------------|----|
|client_id|The identity registered with the provider. Tokens obtained through the authorization code flow must name it as their audience. With `mode=browser` the provider's metadata must also name its issuer and its authorization and token endpoints.|
|client_secret|Omit it for public clients; the exchange is then protected by PKCE alone.|
|redirect_uri|Where the provider sends the user back. It must point at `/sso/callback` on this server and match the value registered with the provider. With 'camouflage' enabled it must also carry the secret as its first query parameter.|
|groups_claim|The claim carrying the user's groups. When absent, group membership is not used.|
|sso_login_timeout|How long the user has to complete the browser login, in seconds. Defaults to 600.|
|sso_max_pending|How many browser logins can be in progress at once. Every login form served starts one, so the number is bounded; further forms are refused until some complete or expire. Defaults to 1024.|
|sso_max_pending_per_ip|How many of those can come from one client address, so that a single client cannot take them all. Many users behind one NAT address share this limit. Defaults to 32.|

The authorization, token and JWKS endpoints are read from the provider's
metadata document, so they do not need to be configured.

Refer to your OpenID Connect provider's documentation for details on claims
and the OpenID Connect metadata document URL.

## Groups

When 'groups_claim' is set, the values of that claim are used as the group
names of the session, which makes 'config-per-group' apply.

Group names are used exactly as the provider sends them, so they must match
the names used elsewhere in the ocserv configuration. Providers which return
hierarchical paths should be configured to send the plain name instead; with
Keycloak this means clearing "Full group path" in the group membership
mapper.

A group is selected by connecting to a URL which names it, e.g.
`https://vpn.example.com/Developers`, with 'select-group-by-url' enabled. The
requested group must be among those in the token, otherwise access is denied.

Unlike the other authentication modules, no group is assigned when the user
did not ask for one. The claim carries every group the user has at the
provider, in no guaranteed order, and some of those may match a
config-per-group entry; choosing one would apply a configuration the user
did not ask for. In that case the session uses the server defaults.

Note that no menu of groups is offered with this authentication method.
The group list of a user is only known from the token of an already
authenticated user, so it cannot be built before the login. Presenting the
groups from 'select-group' instead does not work either: clients with an
embedded browser ignore the selection and submit the first entry of the
list, which would silently place the user in a group they did not choose.
'auto-select-group' is not supported for the same reason.

## Camouflage

The flow works with 'camouflage' enabled. The redirect URI must carry the
secret as its first query parameter, for example
`https://vpn.example.com/sso/callback?SECRET`, and be registered with the
provider in that form; the provider appends its own parameters after it. The
browser is redirected to the final page with the secret as well.

The client recognises the end of the login by comparing the page the browser
loaded with the final URL in the login form. The iOS client needs the two to
match exactly, query included, so it is given the URL with the secret; the
Android client drops the query of the loaded page before comparing, so it is
given the URL without it. Either way the page itself is only reached with the
secret.

The Cisco desktop clients probe the server address without the secret as
part of their captive portal detection, which the check rejects, and they
give up rather than retry. Turning that detection off in the client lets
them connect.

## Example: Keycloak

Create a confidential client in your realm and set:

- *Valid Redirect URIs* to the same value as 'redirect_uri' above
- *Client authentication* on, and copy the secret into 'client_secret'

To pass groups, add a *Group Membership* mapper to the client's dedicated
scope, set the token claim name to `groups`, clear *Full group path*, and
make sure it is added to the ID token.

The corresponding ocserv configuration is:

```
auth = "oidc[config=/etc/ocserv/oidc.json,mode=browser]"
select-group-by-url = true
config-per-group = /etc/ocserv/config-per-group/
```

## Sample token

An OIDC token is returned as a base64url-encoded blob.
`eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJFUzI1NiIsICJraWQiOiAiTXkgRmFrZSBLZXkifQ.eyJhdWQiOiAiU29tZUF1ZGllbmNlIiwgImlzcyI6ICJTb21lSXNzdWVyIiwgImlhdCI6IDE1ODE5ODAzMzcsICJuYmYiOiAxNTgxOTgwMzM3LCAiZXhwIjogMTU4MTk4Mzk5NywgInByZWZlcnJlZF91c2VybmFtZSI6ICJTb21lVXNlciJ9.dBGYHphmSHx_IQp09LpK9wkxAcIqnNRkX2Z59PPe0q7aU8yr2QZrq2fqtqRgk3fJ-LyRFaL5HyKHOHq3xebdXg`

You can view the contents of the token using tools like <https://jwt.ms>.
```
{
  "typ": "JWT",
  "alg": "ES256",
  "kid": "My Fake Key"
}.{
  "aud": "SomeAudience",
  "iss": "SomeIssuer",
  "iat": 1581980337,
  "nbf": 1581980337,
  "exp": 1581983997,
  "preferred_username": "SomeUser"
}.[Signature]
```

|Claim type|Value|Notes|
|--------------|:--------|----:|
|aud|SomeAudience|The "aud" (audience) claim identifies the recipients that the JWT is intended for. Each principal intended to process the JWT MUST identify itself with a value in the audience claim. If the principal processing the claim does not identify itself with a value in the "aud" claim when this claim is present, then the JWT MUST be rejected. [RFC 7519, Section 4.1.3]|
|iss|SomeIssuer|The "iss" (issuer) claim identifies the principal that issued the JWT. The processing of this claim is generally application specific. The "iss" value is a case-sensitive string containing a StringOrURI value. [RFC 7519, Section 4.1.1]|
|iat|Mon Feb 17 2020 15:58:57 GMT-0700 (Mountain Standard Time)|The "iat" (issued at) claim identifies the time at which the JWT was issued. This claim can be used to determine the age of the JWT. [RFC 7519, Section 4.1.6]|
|nbf|Mon Feb 17 2020 15:58:57 GMT-0700 (Mountain Standard Time)|The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing. It is not required by OpenID Connect and is only checked when present. [RFC 7519, Section 4.1.5]|
|exp|Mon Feb 17 2020 16:59:57 GMT-0700 (Mountain Standard Time)|The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing. Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew. [RFC 7519, Section 4.1.4]|
|nonce|(random)|Binds the token to the authorization request which produced it. Generated by ocserv during the authorization code flow and rejected if it does not match. [OpenID Connect Core 1.0, Section 3.1.2.1]|
|preferred_username|SomeUser|Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe. This value MAY be any valid JSON string including special characters such as @, /, or whitespace. The RP MUST NOT rely upon this value being unique, as discussed in OpenID Connect Core 1.0 Section 5.7. [OpenID Connect Core 1.0, Section 5.1]|
