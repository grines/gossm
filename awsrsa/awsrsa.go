//AWS RSA Auth
package awsrsa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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
	"github.com/grines/ssmmm/awsshared"
)

type AwsToken struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	UpdateKeyPair   bool   `json:"UpdateKeyPair"`
}

type DocMessage struct {
	Destination string `json:"Destination"`
	Messages    []struct {
		CreatedDate   time.Time `json:"CreatedDate"`
		Destination   string    `json:"Destination"`
		MessageID     string    `json:"MessageId"`
		Payload       string    `json:"Payload"`
		PayloadDigest string    `json:"PayloadDigest"`
		Topic         string    `json:"Topic"`
	} `json:"Messages"`
	MessagesRequestID string `json:"MessagesRequestId"`
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
		v4.Query.Set("X-Amz-Algorithm", awsshared.AuthHeaderPrefix)
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
			urlValues, unsignedHeaders = buildQuery(awsshared.AllowedQueryHoisting, unsignedHeaders) // no depends
			for k := range urlValues {
				v4.Query[k] = urlValues[k]
			}
		}
	}

	v4.buildCanonicalHeaders(awsshared.IgnoredHeaders, unsignedHeaders)
	v4.buildCanonicalString() // depends on canon headers / signed headers
	v4.buildStringToSign()    // depends on canon string
	v4.buildRsaSignature()    // depends on string to sign

	if v4.isPresign {
		v4.Request.URL.RawQuery += "&X-Amz-Signature=" + v4.signature
	} else {
		parts := []string{
			awsshared.AuthHeaderPrefix + " Credential=" + v4.CredValues.AccessKeyID + "/" + v4.credentialString,
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
		v4.Query.Set("X-Amz-Algorithm", awsshared.AuthHeaderPrefix)
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
			urlValues, unsignedHeaders = buildQuery(awsshared.AllowedQueryHoisting, unsignedHeaders) // no depends
			for k := range urlValues {
				v4.Query[k] = urlValues[k]
			}
		}
	}

	v4.buildCanonicalHeaders(awsshared.IgnoredHeaders, unsignedHeaders)
	v4.buildCanonicalString() // depends on canon headers / signed headers
	v4.buildStringToSign()    // depends on canon string
	v4.buildSignature()       // depends on string to sign

	if v4.isPresign {
		v4.Request.URL.RawQuery += "&X-Amz-Signature=" + v4.signature
	} else {
		parts := []string{
			awsshared.AuthHeaderPrefix + " Credential=" + v4.CredValues.AccessKeyID + "/" + v4.credentialString,
			"SignedHeaders=" + v4.signedHeaders,
			"Signature=" + v4.signature,
		}
		v4.Request.Header.Set("Authorization", strings.Join(parts, ", "))
	}
}

func (v4 *signer) buildTime() {
	v4.formattedTime = v4.Time.UTC().Format(awsshared.TimeFormat)
	v4.formattedShortTime = v4.Time.UTC().Format(awsshared.ShortTimeFormat)

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

func buildQuery(r awsshared.Rule, header http.Header) (url.Values, http.Header) {
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
func (v4 *signer) buildCanonicalHeaders(r awsshared.Rule, header http.Header) {
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

	v4.canonicalHeaders = strings.Join(awsshared.StripExcessSpaces(headerValues), "\n")
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
		awsshared.AuthHeaderPrefix,
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
