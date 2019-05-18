# Amamail-Edge-Auth: Akamai Edge Authorization Token for Go


Amamail-Edge-Auth is Akamai Edge Authorization Token in the HTTP Cookie, Query String and Header for a client.
You can configure it in the Property Manager at https://control.akamai.com.
It's a behavior which is Auth Token 2.0 Verification.


<div style="text-align:center"><img src=https://github.com/AstinCHOI/akamai-asset/blob/master/edgeauth/edgeauth.png?raw=true /></div>


## Build



## Example
```go

```


#### ACL(Access Control List) parameter option
```go


## Usage

#### EdgeAuth, EdgeAuthBuilder Class

| Parameter | Description |
|-----------|-------------|
| tokenName | Parameter name for the new token. [ Default: \_\_token\_\_ ] |
| key | Secret required to generate the token. It must be hexadecimal digit string with even-length. |
| algorithm  | Algorithm to use to generate the token. ("sha1", "sha256", or "md5") [ Default: "sha256" ] |
| ip | IP Address to restrict this token to. (Troublesome in many cases (roaming, NAT, etc) so not often used) |
| payload | Additional text added to the calculated digest. |
| sessionId | The session identifier for single use tokens or other advanced cases. |
| startTime | What is the start time? (Use EdgeAuth.NOW for the current time) |
| endTime | When does this token expire? endTime overrides windowSeconds |
| windowSeconds | How long is this token valid for? |
| fieldDelimiter | Character used to delimit token body fields. [ Default: ~ ] |
| aclDelimiter | Character used to delimit acl. [ Default: ! ] |
| escapeEarly | Causes strings to be url encoded before being used. |
| verbose | Print all parameters. |


