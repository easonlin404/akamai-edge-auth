package edge_auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

type EdgeAuth struct {
	// parameter name for the new token
	TokenName string

	// secret required to generate the token. It must be hexadecimal digit string with even-length
	Key string

	// to use to generate the token. (sha1, sha256, or md5)
	Algorithm string

	// IP Address to restrict this token to. Troublesome in many cases (roaming, NAT, etc) so not often used
	IP string

	// additional text added to the calculated digest.
	Payload string

	// the session identifier for single use tokens or other advanced cases.
	SessionID string

	/** what is the start time? */
	StartTime time.Time

	/** when does this token expire? It overrides {@code windowSeconds} */
	EndTime time.Time

	/** How long is this token valid for? */
	Expiration time.Duration

	/** character used to delimit token body fields. */
	FieldDelimiter string

	/** Character used to delimit acl. */
	AclDelimiter string

	/** causes strings to be url encoded before being used. */
	EscapeEarly bool

	/** print all parameters. */
	Verbose bool

	Logger Logger
}

func New() *EdgeAuth {
	e := &EdgeAuth{}
	e.init()
	return e
}

func (e *EdgeAuth) init() {
	e.TokenName = "__token__"
	e.Algorithm = "sha256"
	e.FieldDelimiter = `~`
	e.AclDelimiter = `!`

	log := log.New(os.Stdout, "", 0)
	e.Logger = log

}

func (e *EdgeAuth) GenerateACLToken(acl string) (string, error) {
	if len(acl) == 0 {
		return "", errors.New("you must provide an ACL")
	}
	return e.generateACLToken(acl, false)
}

func (e *EdgeAuth) generateACLToken(path string, isURL bool) (string, error) {
	startTime := e.StartTime
	endTime := e.EndTime

	now := time.Now()

	if startTime.IsZero() {
		startTime = now
	}

	if endTime.IsZero() {
		endTime = now.Add(e.Expiration)
	}

	if endTime.Before(startTime) {
		return "", errors.New("Token will have already expired")
	}

	if e.Verbose {
		e.Logger.Printf("Akamai Token Generation Parameters\n")
		if isURL {
			e.Logger.Printf("URL             : %s\n", path)
		} else {
			e.Logger.Printf("ACL             : %s\n", path)
		}
		e.Logger.Printf("Token Name      : %s\n", e.TokenName)
		e.Logger.Printf("Key/Secret      : %s\n", e.Key)
		e.Logger.Printf("Algorithm       : %s\n", e.Algorithm)
		e.Logger.Printf("IP              : %s\n", e.IP)
		e.Logger.Printf("Payload         : %s\n", e.Payload)
		e.Logger.Printf("Session ID      : %s\n", e.SessionID)
		e.Logger.Printf("Start Time      : %s\n", e.StartTime)
		e.Logger.Printf("Expiration 		: %s\n", e.Expiration)
		e.Logger.Printf("End Time        : %s\n", e.EndTime)
		e.Logger.Printf("Field Delimiter : %s\n", e.FieldDelimiter)
		e.Logger.Printf("ACL Delimiter   : %s\n", e.AclDelimiter)
		e.Logger.Printf("Escape Early    : %s\n", e.EscapeEarly)
	}

	newToken := ""

	if len(e.IP) > 0 {
		newToken += "ip="
		newToken += e.IP
		newToken += e.FieldDelimiter
	}

	if !e.StartTime.IsZero() {
		newToken += "st="
		newToken += strconv.FormatInt(startTime.Unix(), 10)
		newToken += e.FieldDelimiter
	}

	newToken += "exp="
	newToken += strconv.FormatInt(endTime.Unix(), 10)
	newToken += e.FieldDelimiter

	if !isURL {
		newToken += "acl="
		newToken += path
		newToken += e.FieldDelimiter
	}

	if len(e.SessionID) > 0 {
		newToken += "id="
		newToken += e.SessionID
		newToken += e.FieldDelimiter
	}

	if len(e.Payload) > 0 {
		newToken += "data="
		newToken += e.Payload
		newToken += e.FieldDelimiter
	}

	if e.EscapeEarly {
		newToken = url.PathEscape(newToken)
	}

	hashSource := newToken

	if isURL {
		hashSource += "url="
		hashSource += path
		newToken += e.FieldDelimiter
	}

	hashSource = hashSource[:len(hashSource)-1]

	sha := ""
	switch e.Algorithm {
	case "sha256":
		key, err := hex.DecodeString(e.Key)
		if err != nil {
			return "", errors.WithMessagef(err, "akamai: invalid hex string key: %s", e.Key)
		}

		h := hmac.New(sha256.New, key)
		h.Write([]byte(hashSource))

		sha = hex.EncodeToString(h.Sum(nil))
	}

	return newToken + "hmac=" + sha, nil
}
