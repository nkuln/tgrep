package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

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
