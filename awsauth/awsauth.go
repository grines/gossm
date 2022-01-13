package awsauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/amazon-ssm-agent/agent/managedInstances/auth"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/private/protocol/rest"
)

type AwsToken struct {
	AccessKeyID         string `json:"AccessKeyId"`
	SecretAccessKey     string `json:"SecretAccessKey"`
	SessionToken        string `json:"SessionToken"`
	TokenExpirationDate int    `json:"TokenExpirationDate"`
	UpdateKeyPair       bool   `json:"UpdateKeyPair"`
}

func UniqueID() string {
	uuid := make([]byte, 16)
	io.ReadFull(rand.Reader, uuid)
	return fmt.Sprintf("%x", uuid)
}

func BuildRsaSigner(managedInstanceID string, publicKey string, amzTarget string, serviceName string, region string, signTime time.Time, expireTime time.Duration, body string) signer {

	endpoint := "https://" + serviceName + "." + region + ".amazonaws.com"
	reader := strings.NewReader(body)
	req, _ := http.NewRequest("POST", endpoint, reader)
	req.Header.Add("X-Amz-Target", amzTarget)
	req.Header.Add("Content-Type", "application/x-amz-json-1.1")
	req.Header.Add("Content-Length", fmt.Sprint(len(body)))

	return signer{
		Request:     req,
		Time:        signTime,
		ExpireTime:  expireTime,
		Query:       req.URL.Query(),
		Body:        reader,
		ServiceName: serviceName,
		Region:      region,
		Credentials: credentials.NewStaticCredentials(managedInstanceID, publicKey, ""),
	}
}

func BuildRsaSigner2(accesskey string, secretkey string, sessiontoken string, amzTarget string, serviceName string, region string, signTime time.Time, expireTime time.Duration, body string) signer {

	endpoint := "https://" + serviceName + "." + region + ".amazonaws.com"
	reader := strings.NewReader(body)
	req, _ := http.NewRequest("POST", endpoint, reader)
	req.Header.Add("X-Amz-Target", amzTarget)
	req.Header.Add("Content-Type", "application/x-amz-json-1.1")
	req.Header.Add("Content-Length", fmt.Sprint(len(body)))

	return signer{
		Request:     req,
		Time:        signTime,
		ExpireTime:  expireTime,
		Query:       req.URL.Query(),
		Body:        reader,
		ServiceName: serviceName,
		Region:      region,
		Credentials: credentials.NewStaticCredentials(accesskey, secretkey, sessiontoken),
	}
}

func SignRsa(req *request.Request) {
	// If the request does not need to be signed ignore the signing of the
	// request if the AnonymousCredentials object is used.
	if req.Config.Credentials == credentials.AnonymousCredentials {
		return
	}

	region := req.ClientInfo.SigningRegion
	if region == "" {
		region = aws.StringValue(req.Config.Region)
	}

	name := req.ClientInfo.SigningName
	if name == "" {
		name = req.ClientInfo.ServiceName
	}

	s := signer{
		Request:     req.HTTPRequest,
		Time:        req.Time,
		ExpireTime:  req.ExpireTime,
		Query:       req.HTTPRequest.URL.Query(),
		Body:        req.Body,
		ServiceName: name,
		Region:      region,
		Credentials: req.Config.Credentials,
		Debug:       req.Config.LogLevel.Value(),
		Logger:      req.Config.Logger,
		notHoist:    req.NotHoist,
	}

	req.Error = s.SignRsa()
	req.SignedHeaderVals = s.signedHeaderVals
}

func (v4 *signer) SignRsa() error {
	if v4.ExpireTime != 0 {
		v4.isPresign = true
	}

	if v4.isRequestSigned() {
		if !v4.Credentials.IsExpired() {
			// If the request is already signed, and the credentials have not
			// expired yet ignore the signing request.
			return nil
		}

		// The credentials have expired for this request. The current signing
		// is invalid, and needs to be request because the request will fail.
		if v4.isPresign {
			v4.removePresign()
			// Update the request's query string to ensure the values stays in
			// sync in the case retrieving the new credentials fails.
			v4.Request.URL.RawQuery = v4.Query.Encode()
		}
	}

	var err error
	v4.CredValues, err = v4.Credentials.Get()
	if err != nil {
		return err
	}

	if v4.isPresign {
		v4.Query.Set("X-Amz-Algorithm", authHeaderPrefix)
		if v4.CredValues.SessionToken != "" {
			v4.Query.Set("X-Amz-Security-Token", v4.CredValues.SessionToken)
		} else {
			v4.Query.Del("X-Amz-Security-Token")
		}
	} else if v4.CredValues.SessionToken != "" {
		v4.Request.Header.Set("X-Amz-Security-Token", v4.CredValues.SessionToken)
	}

	v4.buildRsa()

	if v4.Debug.Matches(aws.LogDebugWithSigning) {
		v4.logSigningInfo()
	}

	return nil
}

func (v4 *signer) buildRsa() {

	v4.buildTime()             // no depends
	v4.buildCredentialString() // no depends

	unsignedHeaders := v4.Request.Header
	if v4.isPresign {
		if !v4.notHoist {
			urlValues := url.Values{}
			urlValues, unsignedHeaders = buildQuery(allowedQueryHoisting, unsignedHeaders) // no depends
			for k := range urlValues {
				v4.Query[k] = urlValues[k]
			}
		}
	}

	v4.buildCanonicalHeaders(ignoredHeaders, unsignedHeaders)
	v4.buildCanonicalString() // depends on canon headers / signed headers
	v4.buildStringToSign()    // depends on canon string
	v4.buildRsaSignature()    // depends on string to sign

	if v4.isPresign {
		v4.Request.URL.RawQuery += "&X-Amz-Signature=" + v4.signature
	} else {
		parts := []string{
			authHeaderPrefix + " Credential=" + v4.CredValues.AccessKeyID + "/" + v4.credentialString,
			"SignedHeaders=" + v4.signedHeaders,
			"Signature=" + v4.signature,
		}
		v4.Request.Header.Set("Authorization", strings.Join(parts, ", "))
	}
}

// Sign the stringToSign using the private key
func (v4 *signer) buildRsaSignature() (err error) {
	var rsaKey auth.RsaKey
	rsaKey, err = auth.DecodePrivateKey(v4.CredValues.SecretAccessKey)
	if err != nil {
		return
	}
	v4.signature, err = rsaKey.Sign(v4.stringToSign)
	return
}

// string value
type rules []rule

// rule interface allows for more flexible rules and just simply
// checks whether or not a value adheres to that rule
type rule interface {
	IsValid(value string) bool
}

// IsValid will iterate through all rules and see if any rules
// apply to the value and supports nested rules
func (r rules) IsValid(value string) bool {
	for _, rule := range r {
		if rule.IsValid(value) {
			return true
		}
	}
	return false
}

// mapRule generic rule for maps
type mapRule map[string]struct{}

// IsValid for the map rule satisfies whether it exists in the map
func (m mapRule) IsValid(value string) bool {
	_, ok := m[value]
	return ok
}

// whitelist is a generic rule for whitelisting
type whitelist struct {
	rule
}

// IsValid for whitelist checks if the value is within the whitelist
func (w whitelist) IsValid(value string) bool {
	return w.rule.IsValid(value)
}

// blacklist is a generic rule for blacklisting
type blacklist struct {
	rule
}

// IsValid for whitelist checks if the value is within the whitelist
func (b blacklist) IsValid(value string) bool {
	return !b.rule.IsValid(value)
}

type patterns []string

// IsValid for patterns checks each pattern and returns if a match has
// been found
func (p patterns) IsValid(value string) bool {
	for _, pattern := range p {
		if strings.HasPrefix(http.CanonicalHeaderKey(value), pattern) {
			return true
		}
	}
	return false
}

// inclusiveRules rules allow for rules to depend on one another
type inclusiveRules []rule

// IsValid will return true if all rules are true
func (r inclusiveRules) IsValid(value string) bool {
	for _, rule := range r {
		if !rule.IsValid(value) {
			return false
		}
	}
	return true
}

const (
	authHeaderPrefix = "AWS4-HMAC-SHA256"
	timeFormat       = "20060102T150405Z"
	shortTimeFormat  = "20060102"
)

var ignoredHeaders = rules{
	blacklist{
		mapRule{
			"Authorization": struct{}{},
			"User-Agent":    struct{}{},
		},
	},
}

// requiredSignedHeaders is a whitelist for build canonical headers.
var requiredSignedHeaders = rules{
	whitelist{
		mapRule{
			"Cache-Control":                         struct{}{},
			"Content-Disposition":                   struct{}{},
			"Content-Encoding":                      struct{}{},
			"Content-Language":                      struct{}{},
			"Content-Md5":                           struct{}{},
			"Content-Type":                          struct{}{},
			"Expires":                               struct{}{},
			"If-Match":                              struct{}{},
			"If-Modified-Since":                     struct{}{},
			"If-None-Match":                         struct{}{},
			"If-Unmodified-Since":                   struct{}{},
			"Range":                                 struct{}{},
			"X-Amz-Acl":                             struct{}{},
			"X-Amz-Copy-Source":                     struct{}{},
			"X-Amz-Copy-Source-If-Match":            struct{}{},
			"X-Amz-Copy-Source-If-Modified-Since":   struct{}{},
			"X-Amz-Copy-Source-If-None-Match":       struct{}{},
			"X-Amz-Copy-Source-If-Unmodified-Since": struct{}{},
			"X-Amz-Copy-Source-Range":               struct{}{},
			"X-Amz-Copy-Source-Server-Side-Encryption-Customer-Algorithm": struct{}{},
			"X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key":       struct{}{},
			"X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key-Md5":   struct{}{},
			"X-Amz-Grant-Full-control":                                    struct{}{},
			"X-Amz-Grant-Read":                                            struct{}{},
			"X-Amz-Grant-Read-Acp":                                        struct{}{},
			"X-Amz-Grant-Write":                                           struct{}{},
			"X-Amz-Grant-Write-Acp":                                       struct{}{},
			"X-Amz-Metadata-Directive":                                    struct{}{},
			"X-Amz-Mfa":                                                   struct{}{},
			"X-Amz-Request-Payer":                                         struct{}{},
			"X-Amz-Server-Side-Encryption":                                struct{}{},
			"X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id":                 struct{}{},
			"X-Amz-Server-Side-Encryption-Customer-Algorithm":             struct{}{},
			"X-Amz-Server-Side-Encryption-Customer-Key":                   struct{}{},
			"X-Amz-Server-Side-Encryption-Customer-Key-Md5":               struct{}{},
			"X-Amz-Storage-Class":                                         struct{}{},
			"X-Amz-Website-Redirect-Location":                             struct{}{},
		},
	},
	patterns{"X-Amz-Meta-"},
}

// allowedHoisting is a whitelist for build query headers. The boolean value
// represents whether or not it is a pattern.
var allowedQueryHoisting = inclusiveRules{
	blacklist{requiredSignedHeaders},
	patterns{"X-Amz-"},
}

type signer struct {
	Request     *http.Request
	Time        time.Time
	ExpireTime  time.Duration
	ServiceName string
	Region      string
	CredValues  credentials.Value
	Credentials *credentials.Credentials
	Query       url.Values
	Body        io.ReadSeeker
	Debug       aws.LogLevelType
	Logger      aws.Logger

	isPresign          bool
	formattedTime      string
	formattedShortTime string

	signedHeaders    string
	canonicalHeaders string
	canonicalString  string
	credentialString string
	stringToSign     string
	signature        string
	authorization    string
	notHoist         bool
	signedHeaderVals http.Header
}

// Sign requests with signature version 4.
//
// Will sign the requests with the service config's Credentials object
// Signing is skipped if the credentials is the credentials.AnonymousCredentials
// object.
func sign(req *request.Request) {
	// If the request does not need to be signed ignore the signing of the
	// request if the AnonymousCredentials object is used.
	if req.Config.Credentials == credentials.AnonymousCredentials {
		return
	}

	region := req.ClientInfo.SigningRegion
	if region == "" {
		region = aws.StringValue(req.Config.Region)
	}

	name := req.ClientInfo.SigningName
	if name == "" {
		name = req.ClientInfo.ServiceName
	}

	s := signer{
		Request:     req.HTTPRequest,
		Time:        req.Time,
		ExpireTime:  req.ExpireTime,
		Query:       req.HTTPRequest.URL.Query(),
		Body:        req.Body,
		ServiceName: name,
		Region:      region,
		Credentials: req.Config.Credentials,
		Debug:       req.Config.LogLevel.Value(),
		Logger:      req.Config.Logger,
		notHoist:    req.NotHoist,
	}

	req.Error = s.sign()
	req.Time = s.Time
	req.SignedHeaderVals = s.signedHeaderVals
}

func (v4 *signer) sign() error {
	if v4.ExpireTime != 0 {
		v4.isPresign = true
	}

	if v4.isRequestSigned() {
		if !v4.Credentials.IsExpired() && time.Now().Before(v4.Time.Add(10*time.Minute)) {
			// If the request is already signed, and the credentials have not
			// expired, and the request is not too old ignore the signing request.
			return nil
		}
		v4.Time = time.Now()

		// The credentials have expired for this request. The current signing
		// is invalid, and needs to be request because the request will fail.
		if v4.isPresign {
			v4.removePresign()
			// Update the request's query string to ensure the values stays in
			// sync in the case retrieving the new credentials fails.
			v4.Request.URL.RawQuery = v4.Query.Encode()
		}
	}

	var err error
	v4.CredValues, err = v4.Credentials.Get()
	if err != nil {
		return err
	}

	if v4.isPresign {
		v4.Query.Set("X-Amz-Algorithm", authHeaderPrefix)
		if v4.CredValues.SessionToken != "" {
			v4.Query.Set("X-Amz-Security-Token", v4.CredValues.SessionToken)
		} else {
			v4.Query.Del("X-Amz-Security-Token")
		}
	} else if v4.CredValues.SessionToken != "" {
		v4.Request.Header.Set("X-Amz-Security-Token", v4.CredValues.SessionToken)
	}

	v4.build()

	if v4.Debug.Matches(aws.LogDebugWithSigning) {
		v4.logSigningInfo()
	}

	return nil
}

const logSignInfoMsg = `DEBUG: Request Signiture:
---[ CANONICAL STRING  ]-----------------------------
%s
---[ STRING TO SIGN ]--------------------------------
%s%s
-----------------------------------------------------`
const logSignedURLMsg = `
---[ SIGNED URL ]------------------------------------
%s`

func (v4 *signer) logSigningInfo() {
	signedURLMsg := ""
	if v4.isPresign {
		signedURLMsg = fmt.Sprintf(logSignedURLMsg, v4.Request.URL.String())
	}
	msg := fmt.Sprintf(logSignInfoMsg, v4.canonicalString, v4.stringToSign, signedURLMsg)
	v4.Logger.Log(msg)
}

func (v4 *signer) build() {

	v4.buildTime()             // no depends
	v4.buildCredentialString() // no depends

	unsignedHeaders := v4.Request.Header
	if v4.isPresign {
		if !v4.notHoist {
			urlValues := url.Values{}
			urlValues, unsignedHeaders = buildQuery(allowedQueryHoisting, unsignedHeaders) // no depends
			for k := range urlValues {
				v4.Query[k] = urlValues[k]
			}
		}
	}

	v4.buildCanonicalHeaders(ignoredHeaders, unsignedHeaders)
	v4.buildCanonicalString() // depends on canon headers / signed headers
	v4.buildStringToSign()    // depends on canon string
	v4.buildSignature()       // depends on string to sign

	if v4.isPresign {
		v4.Request.URL.RawQuery += "&X-Amz-Signature=" + v4.signature
	} else {
		parts := []string{
			authHeaderPrefix + " Credential=" + v4.CredValues.AccessKeyID + "/" + v4.credentialString,
			"SignedHeaders=" + v4.signedHeaders,
			"Signature=" + v4.signature,
		}
		v4.Request.Header.Set("Authorization", strings.Join(parts, ", "))
	}
}

func (v4 *signer) buildTime() {
	v4.formattedTime = v4.Time.UTC().Format(timeFormat)
	v4.formattedShortTime = v4.Time.UTC().Format(shortTimeFormat)

	if v4.isPresign {
		duration := int64(v4.ExpireTime / time.Second)
		v4.Query.Set("X-Amz-Date", v4.formattedTime)
		v4.Query.Set("X-Amz-Expires", strconv.FormatInt(duration, 10))
	} else {
		v4.Request.Header.Set("X-Amz-Date", v4.formattedTime)
	}
}

func (v4 *signer) buildCredentialString() {
	v4.credentialString = strings.Join([]string{
		v4.formattedShortTime,
		v4.Region,
		v4.ServiceName,
		"aws4_request",
	}, "/")

	if v4.isPresign {
		v4.Query.Set("X-Amz-Credential", v4.CredValues.AccessKeyID+"/"+v4.credentialString)
	}
}

func buildQuery(r rule, header http.Header) (url.Values, http.Header) {
	query := url.Values{}
	unsignedHeaders := http.Header{}
	for k, h := range header {
		if r.IsValid(k) {
			query[k] = h
		} else {
			unsignedHeaders[k] = h
		}
	}

	return query, unsignedHeaders
}
func (v4 *signer) buildCanonicalHeaders(r rule, header http.Header) {
	var headers []string
	headers = append(headers, "host")
	for k, v := range header {
		canonicalKey := http.CanonicalHeaderKey(k)
		if !r.IsValid(canonicalKey) {
			continue // ignored header
		}
		if v4.signedHeaderVals == nil {
			v4.signedHeaderVals = make(http.Header)
		}

		lowerCaseKey := strings.ToLower(k)
		if _, ok := v4.signedHeaderVals[lowerCaseKey]; ok {
			// include additional values
			v4.signedHeaderVals[lowerCaseKey] = append(v4.signedHeaderVals[lowerCaseKey], v...)
			continue
		}

		headers = append(headers, lowerCaseKey)
		v4.signedHeaderVals[lowerCaseKey] = v
	}
	sort.Strings(headers)

	v4.signedHeaders = strings.Join(headers, ";")

	if v4.isPresign {
		v4.Query.Set("X-Amz-SignedHeaders", v4.signedHeaders)
	}

	headerValues := make([]string, len(headers))
	for i, k := range headers {
		if k == "host" {
			headerValues[i] = "host:" + v4.Request.URL.Host
		} else {
			headerValues[i] = k + ":" +
				strings.Join(v4.signedHeaderVals[k], ",")
		}
	}

	v4.canonicalHeaders = strings.Join(stripExcessSpaces(headerValues), "\n")
}

func (v4 *signer) buildCanonicalString() {
	v4.Request.URL.RawQuery = strings.Replace(v4.Query.Encode(), "+", "%20", -1)
	uri := v4.Request.URL.Opaque
	if uri != "" {
		uri = "/" + strings.Join(strings.Split(uri, "/")[3:], "/")
	} else {
		uri = v4.Request.URL.Path
	}
	if uri == "" {
		uri = "/"
	}

	if v4.ServiceName != "s3" {
		uri = rest.EscapePath(uri, false)
	}

	v4.canonicalString = strings.Join([]string{
		v4.Request.Method,
		uri,
		v4.Request.URL.RawQuery,
		v4.canonicalHeaders + "\n",
		v4.signedHeaders,
		v4.bodyDigest(),
	}, "\n")
}

func (v4 *signer) buildStringToSign() {
	v4.stringToSign = strings.Join([]string{
		authHeaderPrefix,
		v4.formattedTime,
		v4.credentialString,
		hex.EncodeToString(makeSha256([]byte(v4.canonicalString))),
	}, "\n")
}

func (v4 *signer) buildSignature() {
	secret := v4.CredValues.SecretAccessKey
	date := makeHmac([]byte("AWS4"+secret), []byte(v4.formattedShortTime))
	region := makeHmac(date, []byte(v4.Region))
	service := makeHmac(region, []byte(v4.ServiceName))
	credentials := makeHmac(service, []byte("aws4_request"))
	signature := makeHmac(credentials, []byte(v4.stringToSign))
	v4.signature = hex.EncodeToString(signature)
}

func (v4 *signer) bodyDigest() string {
	hash := v4.Request.Header.Get("X-Amz-Content-Sha256")
	if hash == "" {
		if v4.isPresign && v4.ServiceName == "s3" {
			hash = "UNSIGNED-PAYLOAD"
		} else if v4.Body == nil {
			hash = hex.EncodeToString(makeSha256([]byte{}))
		} else {
			hash = hex.EncodeToString(makeSha256Reader(v4.Body))
		}
		v4.Request.Header.Add("X-Amz-Content-Sha256", hash)
	}
	return hash
}

// isRequestSigned returns if the request is currently signed or presigned
func (v4 *signer) isRequestSigned() bool {
	if v4.isPresign && v4.Query.Get("X-Amz-Signature") != "" {
		return true
	}
	if v4.Request.Header.Get("Authorization") != "" {
		return true
	}

	return false
}

// unsign removes signing flags for both signed and presigned requests.
func (v4 *signer) removePresign() {
	v4.Query.Del("X-Amz-Algorithm")
	v4.Query.Del("X-Amz-Signature")
	v4.Query.Del("X-Amz-Security-Token")
	v4.Query.Del("X-Amz-Date")
	v4.Query.Del("X-Amz-Expires")
	v4.Query.Del("X-Amz-Credential")
	v4.Query.Del("X-Amz-SignedHeaders")
}

func makeHmac(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func makeSha256(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

func makeSha256Reader(reader io.ReadSeeker) []byte {
	hash := sha256.New()
	start, _ := reader.Seek(0, 1)
	defer reader.Seek(start, 0)

	io.Copy(hash, reader)
	return hash.Sum(nil)
}

func stripExcessSpaces(headerVals []string) []string {
	vals := make([]string, len(headerVals))
	for i, str := range headerVals {
		stripped := ""
		found := false
		str = strings.TrimSpace(str)
		for _, c := range str {
			if !found && c == ' ' {
				stripped += string(c)
				found = true
			} else if c != ' ' {
				stripped += string(c)
				found = false
			}
		}
		vals[i] = stripped
	}
	return vals
}

//AWS v4 proper

type Signer struct {
	// The authentication credentials the request will be signed against.
	// This value must be set to sign requests.
	Credentials *credentials.Credentials

	// Sets the log level the signer should use when reporting information to
	// the logger. If the logger is nil nothing will be logged. See
	// aws.LogLevelType for more information on available logging levels
	//
	// By default nothing will be logged.
	Debug aws.LogLevelType

	// The logger loging information will be written to. If there the logger
	// is nil, nothing will be logged.
	Logger aws.Logger

	// Disables the Signer's moving HTTP header key/value pairs from the HTTP
	// request header to the request's query string. This is most commonly used
	// with pre-signed requests preventing headers from being added to the
	// request's query string.
	DisableHeaderHoisting bool

	// Disables the automatic escaping of the URI path of the request for the
	// siganture's canonical string's path. For services that do not need additional
	// escaping then use this to disable the signer escaping the path.
	//
	// S3 is an example of a service that does not need additional escaping.
	//
	// http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
	DisableURIPathEscaping bool

	// Disables the automatical setting of the HTTP request's Body field with the
	// io.ReadSeeker passed in to the signer. This is useful if you're using a
	// custom wrapper around the body for the io.ReadSeeker and want to preserve
	// the Body value on the Request.Body.
	//
	// This does run the risk of signing a request with a body that will not be
	// sent in the request. Need to ensure that the underlying data of the Body
	// values are the same.
	DisableRequestBodyOverwrite bool

	// currentTimeFn returns the time value which represents the current time.
	// This value should only be used for testing. If it is nil the default
	// time.Now will be used.
	currentTimeFn func() time.Time

	// UnsignedPayload will prevent signing of the payload. This will only
	// work for services that have support for this.
	UnsignedPayload bool
}

func buildRequestWithBodyReader(serviceName, region string, body io.Reader) (*http.Request, io.ReadSeeker) {
	var bodyLen int

	type lenner interface {
		Len() int
	}
	if lr, ok := body.(lenner); ok {
		bodyLen = lr.Len()
	}

	endpoint := "https://" + serviceName + "." + region + ".amazonaws.com"
	req, _ := http.NewRequest("POST", endpoint, body)
	req.Header.Set("X-Amz-Target", "EC2WindowsMessageDeliveryService.GetMessages")
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")

	if bodyLen > 0 {
		req.Header.Set("Content-Length", strconv.Itoa(bodyLen))
	}

	var seeker io.ReadSeeker
	if sr, ok := body.(io.ReadSeeker); ok {
		seeker = sr
	} else {
		seeker = aws.ReadSeekCloser(body)
	}

	return req, seeker
}

func BuildRequest(serviceName, region, body string) (*http.Request, io.ReadSeeker) {
	reader := strings.NewReader(body)
	return buildRequestWithBodyReader(serviceName, region, reader)
}

func BuildSigner(access string, secret string, session string) Signer {
	return Signer{
		Credentials: credentials.NewStaticCredentials(access, secret, session),
	}
}

func epochTime() time.Time { return time.Unix(0, 0) }

const (
	authorizationHeader     = "Authorization"
	authHeaderSignatureElem = "Signature="
	signatureQueryKey       = "X-Amz-Signature"

	awsV4Request = "aws4_request"

	// emptyStringSHA256 is a SHA256 of an empty string
	emptyStringSHA256 = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
)

func NewSigner(credentials *credentials.Credentials, options ...func(*Signer)) *Signer {
	v4 := &Signer{
		Credentials: credentials,
	}

	for _, option := range options {
		option(v4)
	}

	return v4
}

type signingCtx struct {
	ServiceName      string
	Region           string
	Request          *http.Request
	Body             io.ReadSeeker
	Query            url.Values
	Time             time.Time
	ExpireTime       time.Duration
	SignedHeaderVals http.Header

	DisableURIPathEscaping bool

	credValues      credentials.Value
	isPresign       bool
	unsignedPayload bool

	bodyDigest       string
	signedHeaders    string
	canonicalHeaders string
	canonicalString  string
	credentialString string
	stringToSign     string
	signature        string
	authorization    string
}

func (v4 Signer) Sign(r *http.Request, body io.ReadSeeker, service, region string, signTime time.Time) (http.Header, error) {
	return v4.signWithBody(r, body, service, region, 0, false, signTime)
}

func (v4 Signer) Presign(r *http.Request, body io.ReadSeeker, service, region string, exp time.Duration, signTime time.Time) (http.Header, error) {
	return v4.signWithBody(r, body, service, region, exp, true, signTime)
}

func requestContext(r *http.Request) aws.Context {
	return aws.BackgroundContext()
}

func (v4 Signer) signWithBody(r *http.Request, body io.ReadSeeker, service, region string, exp time.Duration, isPresign bool, signTime time.Time) (http.Header, error) {
	currentTimeFn := v4.currentTimeFn
	if currentTimeFn == nil {
		currentTimeFn = time.Now
	}

	ctx := &signingCtx{
		Request:                r,
		Body:                   body,
		Query:                  r.URL.Query(),
		Time:                   signTime,
		ExpireTime:             exp,
		isPresign:              isPresign,
		ServiceName:            service,
		Region:                 region,
		DisableURIPathEscaping: v4.DisableURIPathEscaping,
		unsignedPayload:        v4.UnsignedPayload,
	}

	for key := range ctx.Query {
		sort.Strings(ctx.Query[key])
	}

	if ctx.isRequestSigned() {
		ctx.Time = currentTimeFn()
		ctx.handlePresignRemoval()
	}

	var err error
	ctx.credValues, err = v4.Credentials.GetWithContext(requestContext(r))
	if err != nil {
		return http.Header{}, err
	}

	ctx.sanitizeHostForHeader()
	ctx.assignAmzQueryValues()
	if err := ctx.build(v4.DisableHeaderHoisting); err != nil {
		return nil, err
	}

	// If the request is not presigned the body should be attached to it. This
	// prevents the confusion of wanting to send a signed request without
	// the body the request was signed for attached.
	if !(v4.DisableRequestBodyOverwrite || ctx.isPresign) {
		var reader io.ReadCloser
		if body != nil {
			var ok bool
			if reader, ok = body.(io.ReadCloser); !ok {
				reader = ioutil.NopCloser(body)
			}
		}
		r.Body = reader
	}

	if v4.Debug.Matches(aws.LogDebugWithSigning) {
		v4.logSigningInfo(ctx)
	}

	return ctx.SignedHeaderVals, nil
}

func (ctx *signingCtx) sanitizeHostForHeader() {
	request.SanitizeHostForHeader(ctx.Request)
}

func (ctx *signingCtx) handlePresignRemoval() {
	if !ctx.isPresign {
		return
	}

	// The credentials have expired for this request. The current signing
	// is invalid, and needs to be request because the request will fail.
	ctx.removePresign()

	// Update the request's query string to ensure the values stays in
	// sync in the case retrieving the new credentials fails.
	ctx.Request.URL.RawQuery = ctx.Query.Encode()
}

func (ctx *signingCtx) assignAmzQueryValues() {
	if ctx.isPresign {
		ctx.Query.Set("X-Amz-Algorithm", authHeaderPrefix)
		if ctx.credValues.SessionToken != "" {
			ctx.Query.Set("X-Amz-Security-Token", ctx.credValues.SessionToken)
		} else {
			ctx.Query.Del("X-Amz-Security-Token")
		}

		return
	}

	if ctx.credValues.SessionToken != "" {
		ctx.Request.Header.Set("X-Amz-Security-Token", ctx.credValues.SessionToken)
	}
}

// SignRequestHandler is a named request handler the SDK will use to sign
// service client request with using the V4 signature.
var SignRequestHandler = request.NamedHandler{
	Name: "v4.SignRequestHandler", Fn: SignSDKRequest,
}

// SignSDKRequest signs an AWS request with the V4 signature. This
// request handler should only be used with the SDK's built in service client's
// API operation requests.
//
// This function should not be used on its own, but in conjunction with
// an AWS service client's API operation call. To sign a standalone request
// not created by a service client's API operation method use the "Sign" or
// "Presign" functions of the "Signer" type.
//
// If the credentials of the request's config are set to
// credentials.AnonymousCredentials the request will not be signed.
func SignSDKRequest(req *request.Request) {
	SignSDKRequestWithCurrentTime(req, time.Now)
}

// BuildNamedHandler will build a generic handler for signing.
func BuildNamedHandler(name string, opts ...func(*Signer)) request.NamedHandler {
	return request.NamedHandler{
		Name: name,
		Fn: func(req *request.Request) {
			SignSDKRequestWithCurrentTime(req, time.Now, opts...)
		},
	}
}

// SignSDKRequestWithCurrentTime will sign the SDK's request using the time
// function passed in. Behaves the same as SignSDKRequest with the exception
// the request is signed with the value returned by the current time function.
func SignSDKRequestWithCurrentTime(req *request.Request, curTimeFn func() time.Time, opts ...func(*Signer)) {
	// If the request does not need to be signed ignore the signing of the
	// request if the AnonymousCredentials object is used.
	if req.Config.Credentials == credentials.AnonymousCredentials {
		return
	}

	region := req.ClientInfo.SigningRegion
	if region == "" {
		region = aws.StringValue(req.Config.Region)
	}

	name := req.ClientInfo.SigningName
	if name == "" {
		name = req.ClientInfo.ServiceName
	}

	v4 := NewSigner(req.Config.Credentials, func(v4 *Signer) {
		v4.Debug = req.Config.LogLevel.Value()
		v4.Logger = req.Config.Logger
		v4.DisableHeaderHoisting = req.NotHoist
		v4.currentTimeFn = curTimeFn
		if name == "s3" {
			// S3 service should not have any escaping applied
			v4.DisableURIPathEscaping = true
		}
		// Prevents setting the HTTPRequest's Body. Since the Body could be
		// wrapped in a custom io.Closer that we do not want to be stompped
		// on top of by the signer.
		v4.DisableRequestBodyOverwrite = true
	})

	for _, opt := range opts {
		opt(v4)
	}

	curTime := curTimeFn()
	signedHeaders, err := v4.signWithBody(req.HTTPRequest, req.GetBody(),
		name, region, req.ExpireTime, req.ExpireTime > 0, curTime,
	)
	if err != nil {
		req.Error = err
		req.SignedHeaderVals = nil
		return
	}

	req.SignedHeaderVals = signedHeaders
	req.LastSignedAt = curTime
}

func (v4 *Signer) logSigningInfo(ctx *signingCtx) {
	signedURLMsg := ""
	if ctx.isPresign {
		signedURLMsg = fmt.Sprintf(logSignedURLMsg, ctx.Request.URL.String())
	}
	msg := fmt.Sprintf(logSignInfoMsg, ctx.canonicalString, ctx.stringToSign, signedURLMsg)
	v4.Logger.Log(msg)
}

func (ctx *signingCtx) build(disableHeaderHoisting bool) error {
	ctx.buildTime()             // no depends
	ctx.buildCredentialString() // no depends

	if err := ctx.buildBodyDigest(); err != nil {
		return err
	}

	unsignedHeaders := ctx.Request.Header
	if ctx.isPresign {
		if !disableHeaderHoisting {
			urlValues := url.Values{}
			urlValues, unsignedHeaders = buildQuery(allowedQueryHoisting, unsignedHeaders) // no depends
			for k := range urlValues {
				ctx.Query[k] = urlValues[k]
			}
		}
	}

	ctx.buildCanonicalHeaders(ignoredHeaders, unsignedHeaders)
	ctx.buildCanonicalString() // depends on canon headers / signed headers
	ctx.buildStringToSign()    // depends on canon string
	ctx.buildSignature()       // depends on string to sign

	if ctx.isPresign {
		ctx.Request.URL.RawQuery += "&" + signatureQueryKey + "=" + ctx.signature
	} else {
		parts := []string{
			authHeaderPrefix + " Credential=" + ctx.credValues.AccessKeyID + "/" + ctx.credentialString,
			"SignedHeaders=" + ctx.signedHeaders,
			authHeaderSignatureElem + ctx.signature,
		}
		ctx.Request.Header.Set(authorizationHeader, strings.Join(parts, ", "))
	}

	return nil
}

// GetSignedRequestSignature attempts to extract the signature of the request.
// Returning an error if the request is unsigned, or unable to extract the
// signature.
func GetSignedRequestSignature(r *http.Request) ([]byte, error) {

	if auth := r.Header.Get(authorizationHeader); len(auth) != 0 {
		ps := strings.Split(auth, ", ")
		for _, p := range ps {
			if idx := strings.Index(p, authHeaderSignatureElem); idx >= 0 {
				sig := p[len(authHeaderSignatureElem):]
				if len(sig) == 0 {
					return nil, fmt.Errorf("invalid request signature authorization header")
				}
				return hex.DecodeString(sig)
			}
		}
	}

	if sig := r.URL.Query().Get("X-Amz-Signature"); len(sig) != 0 {
		return hex.DecodeString(sig)
	}

	return nil, fmt.Errorf("request not signed")
}

func (ctx *signingCtx) buildTime() {
	if ctx.isPresign {
		duration := int64(ctx.ExpireTime / time.Second)
		ctx.Query.Set("X-Amz-Date", formatTime(ctx.Time))
		ctx.Query.Set("X-Amz-Expires", strconv.FormatInt(duration, 10))
	} else {
		ctx.Request.Header.Set("X-Amz-Date", formatTime(ctx.Time))
	}
}

func (ctx *signingCtx) buildCredentialString() {
	ctx.credentialString = buildSigningScope(ctx.Region, ctx.ServiceName, ctx.Time)

	if ctx.isPresign {
		ctx.Query.Set("X-Amz-Credential", ctx.credValues.AccessKeyID+"/"+ctx.credentialString)
	}
}

func (ctx *signingCtx) buildCanonicalHeaders(r rule, header http.Header) {
	var headers []string
	headers = append(headers, "host")
	for k, v := range header {
		if !r.IsValid(k) {
			continue // ignored header
		}
		if ctx.SignedHeaderVals == nil {
			ctx.SignedHeaderVals = make(http.Header)
		}

		lowerCaseKey := strings.ToLower(k)
		if _, ok := ctx.SignedHeaderVals[lowerCaseKey]; ok {
			// include additional values
			ctx.SignedHeaderVals[lowerCaseKey] = append(ctx.SignedHeaderVals[lowerCaseKey], v...)
			continue
		}

		headers = append(headers, lowerCaseKey)
		ctx.SignedHeaderVals[lowerCaseKey] = v
	}
	sort.Strings(headers)

	ctx.signedHeaders = strings.Join(headers, ";")

	if ctx.isPresign {
		ctx.Query.Set("X-Amz-SignedHeaders", ctx.signedHeaders)
	}

	headerItems := make([]string, len(headers))
	for i, k := range headers {
		if k == "host" {
			if ctx.Request.Host != "" {
				headerItems[i] = "host:" + ctx.Request.Host
			} else {
				headerItems[i] = "host:" + ctx.Request.URL.Host
			}
		} else {
			headerValues := make([]string, len(ctx.SignedHeaderVals[k]))
			for i, v := range ctx.SignedHeaderVals[k] {
				headerValues[i] = strings.TrimSpace(v)
			}
			headerItems[i] = k + ":" +
				strings.Join(headerValues, ",")
		}
	}
	stripExcessSpaces(headerItems)
	ctx.canonicalHeaders = strings.Join(headerItems, "\n")
}

func getURIPath(u *url.URL) string {
	var uri string

	if len(u.Opaque) > 0 {
		uri = "/" + strings.Join(strings.Split(u.Opaque, "/")[3:], "/")
	} else {
		uri = u.EscapedPath()
	}

	if len(uri) == 0 {
		uri = "/"
	}

	return uri
}

func (ctx *signingCtx) buildCanonicalString() {
	ctx.Request.URL.RawQuery = strings.Replace(ctx.Query.Encode(), "+", "%20", -1)

	uri := getURIPath(ctx.Request.URL)

	if !ctx.DisableURIPathEscaping {
		uri = rest.EscapePath(uri, false)
	}

	ctx.canonicalString = strings.Join([]string{
		ctx.Request.Method,
		uri,
		ctx.Request.URL.RawQuery,
		ctx.canonicalHeaders + "\n",
		ctx.signedHeaders,
		ctx.bodyDigest,
	}, "\n")
}

func (ctx *signingCtx) buildStringToSign() {
	ctx.stringToSign = strings.Join([]string{
		authHeaderPrefix,
		formatTime(ctx.Time),
		ctx.credentialString,
		hex.EncodeToString(hashSHA256([]byte(ctx.canonicalString))),
	}, "\n")
}

func (ctx *signingCtx) buildSignature() {
	creds := deriveSigningKey(ctx.Region, ctx.ServiceName, ctx.credValues.SecretAccessKey, ctx.Time)
	signature := hmacSHA256(creds, []byte(ctx.stringToSign))
	ctx.signature = hex.EncodeToString(signature)
}

func makeSha256Reader2(reader io.ReadSeeker) (hashBytes []byte, err error) {
	hash := sha256.New()
	start, err := reader.Seek(0, SeekCurrent)
	if err != nil {
		return nil, err
	}
	defer func() {
		// ensure error is return if unable to seek back to start of payload.
		_, err = reader.Seek(start, SeekStart)
	}()

	// Use CopyN to avoid allocating the 32KB buffer in io.Copy for bodies
	// smaller than 32KB. Fall back to io.Copy if we fail to determine the size.
	size, err := aws.SeekerLen(reader)
	if err != nil {
		io.Copy(hash, reader)
	} else {
		io.CopyN(hash, reader, size)
	}

	return hash.Sum(nil), nil
}

func (ctx *signingCtx) buildBodyDigest() error {
	hash := ctx.Request.Header.Get("X-Amz-Content-Sha256")
	if hash == "" {
		includeSHA256Header := ctx.unsignedPayload ||
			ctx.ServiceName == "s3" ||
			ctx.ServiceName == "s3-object-lambda" ||
			ctx.ServiceName == "glacier"

		s3Presign := ctx.isPresign &&
			(ctx.ServiceName == "s3" ||
				ctx.ServiceName == "s3-object-lambda")

		if ctx.unsignedPayload || s3Presign {
			hash = "UNSIGNED-PAYLOAD"
			includeSHA256Header = !s3Presign
		} else if ctx.Body == nil {
			hash = emptyStringSHA256
		} else {
			if !aws.IsReaderSeekable(ctx.Body) {
				return fmt.Errorf("cannot use unseekable request body %T, for signed request with body", ctx.Body)
			}
			hashBytes, err := makeSha256Reader2(ctx.Body)
			if err != nil {
				return err
			}
			hash = hex.EncodeToString(hashBytes)
		}

		if includeSHA256Header {
			ctx.Request.Header.Set("X-Amz-Content-Sha256", hash)
		}
	}
	ctx.bodyDigest = hash

	return nil
}

// isRequestSigned returns if the request is currently signed or presigned
func (ctx *signingCtx) isRequestSigned() bool {
	if ctx.isPresign && ctx.Query.Get("X-Amz-Signature") != "" {
		return true
	}
	if ctx.Request.Header.Get("Authorization") != "" {
		return true
	}

	return false
}

// unsign removes signing flags for both signed and presigned requests.
func (ctx *signingCtx) removePresign() {
	ctx.Query.Del("X-Amz-Algorithm")
	ctx.Query.Del("X-Amz-Signature")
	ctx.Query.Del("X-Amz-Security-Token")
	ctx.Query.Del("X-Amz-Date")
	ctx.Query.Del("X-Amz-Expires")
	ctx.Query.Del("X-Amz-Credential")
	ctx.Query.Del("X-Amz-SignedHeaders")
}

func hmacSHA256(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func hashSHA256(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

const doubleSpace = "  "

func buildSigningScope(region, service string, dt time.Time) string {
	return strings.Join([]string{
		formatShortTime(dt),
		region,
		service,
		awsV4Request,
	}, "/")
}

func deriveSigningKey(region, service, secretKey string, dt time.Time) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(formatShortTime(dt)))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	signingKey := hmacSHA256(kService, []byte(awsV4Request))
	return signingKey
}

func formatShortTime(dt time.Time) string {
	return dt.UTC().Format(shortTimeFormat)
}

func formatTime(dt time.Time) string {
	return dt.UTC().Format(timeFormat)
}

// Alias for Go 1.7 io package Seeker constants
const (
	SeekStart   = io.SeekStart   // seek relative to the origin of the file
	SeekCurrent = io.SeekCurrent // seek relative to the current offset
	SeekEnd     = io.SeekEnd     // seek relative to the end
)
