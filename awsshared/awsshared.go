//shared between auth packages
package awsshared

import (
	"net/http"
	"net/url"
	"strings"
)

// string value
type rules []Rule

// rule interface allows for more flexible rules and just simply
// checks whether or not a value adheres to that rule
type Rule interface {
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
	Rule
}

// IsValid for whitelist checks if the value is within the whitelist
func (w whitelist) IsValid(value string) bool {
	return w.Rule.IsValid(value)
}

// blacklist is a generic rule for blacklisting
type blacklist struct {
	Rule
}

// IsValid for whitelist checks if the value is within the whitelist
func (b blacklist) IsValid(value string) bool {
	return !b.Rule.IsValid(value)
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
type inclusiveRules []Rule

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
	AuthHeaderPrefix = "AWS4-HMAC-SHA256"
	TimeFormat       = "20060102T150405Z"
	ShortTimeFormat  = "20060102"
)

var IgnoredHeaders = rules{
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
var AllowedQueryHoisting = inclusiveRules{
	blacklist{requiredSignedHeaders},
	patterns{"X-Amz-"},
}

const LogSignInfoMsg = `DEBUG: Request Signiture:
---[ CANONICAL STRING  ]-----------------------------
%s
---[ STRING TO SIGN ]--------------------------------
%s%s
-----------------------------------------------------`
const LogSignedURLMsg = `
---[ SIGNED URL ]------------------------------------
%s`

func BuildQuery(r Rule, header http.Header) (url.Values, http.Header) {
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

func StripExcessSpaces(headerVals []string) []string {
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
