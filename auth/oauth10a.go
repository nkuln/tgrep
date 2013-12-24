package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var nonWordCharsRe = regexp.MustCompile("[^a-zA-Z0-9]")

var currentTimeMillis = func() int64 {
	return time.Now().Unix()
}

var randomBase64String = func(numbytes int) (string, error) {
	bound := big.NewInt(0)
	bound.SetBit(bound, 8*numbytes, 1)
	randnum, err := randomBigInt(rand.Reader, bound)
	if err != nil {
		return "", err
	}
	base64Encoded := base64.StdEncoding.EncodeToString(randnum.Bytes())
	return nonWordCharsRe.ReplaceAllLiteralString(base64Encoded, ""), nil
}

var randomBigInt = func(reader io.Reader, max *big.Int) (*big.Int, error) {
	return rand.Int(reader, max)
}

func MakeAuthorizedRequest(consumerKey, consumerSecret,
	tokenSecret, accessToken, method, baseUrl string,
	params map[string]string) (*http.Request, error) {
	data := url.Values{}
	for key, value := range params {
		data.Set(key, value)
	}
	req, err := http.NewRequest(method, baseUrl,
		bytes.NewBufferString(data.Encode()))
	if err != nil {
		return req, err
	}
	nonce, err := randomBase64String(32)
	if err != nil {
		return nil, err
	}
	oauthParams := map[string]string{
		"oauth_consumer_key":     consumerKey,
		"oauth_nonce":            nonce,
		"oauth_signature_method": "HMAC-SHA1",
		"oauth_timestamp":        fmt.Sprintf("%d", currentTimeMillis()),
		"oauth_token":            accessToken,
		"oauth_version":          "1.0",
	}
	for key, value := range oauthParams {
		params[key] = value
	}
	oauthParams["oauth_signature"] = GetSignature(consumerSecret, tokenSecret,
		method, baseUrl, params)
	parts := []string{}
	for key, value := range oauthParams {
		parts = append(parts, fmt.Sprintf(`%s="%s"`,
			percentEncode(key), percentEncode(value)))
	}
	sort.Strings(parts)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization",
		fmt.Sprintf("OAuth %s", strings.Join(parts, ", ")))
	return req, err
}

func GetSignature(consumerSecret, tokenSecret, method, baseUrl string,
	params map[string]string) string {
	basestr := getSignatureBaseString(
		method, baseUrl, getParameterString(params))
	key := []byte(getSigningKey(consumerSecret, tokenSecret))
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(basestr))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return signature
}

func getParameterString(params map[string]string) string {
	encoded := []string{}
	for key, value := range params {
		encoded = append(encoded,
			fmt.Sprintf("%s=%s", percentEncode(key), percentEncode(value)))
	}
	sort.Strings(encoded)
	return strings.Join(encoded, "&")
}

func getSignatureBaseString(
	method string, baseUrl string, paramString string) string {
	return fmt.Sprintf("%s&%s&%s", strings.ToUpper(method),
		percentEncode(baseUrl), percentEncode(paramString))
}

func getSigningKey(consumerSecret string, tokenSecret string) string {
	return fmt.Sprintf("%s&%s", percentEncode(consumerSecret),
		percentEncode(tokenSecret))
}

func percentEncode(s string) string {
	ret := url.QueryEscape(s)
	return strings.Replace(ret, "+", "%20", -1)
}
