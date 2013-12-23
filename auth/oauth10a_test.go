package auth

import (
	"testing"
)

func TestGetSignature(t *testing.T) {
	type TestCase struct {
		cs, ts      string
		method, url string
		params      map[string]string
		expected    string
	}
	golden := []TestCase{
		TestCase{
			"kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
			"LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
			"Post", "https://api.twitter.com/1/statuses/update.json",
			map[string]string{
				"status":                 "Hello Ladies + Gentlemen, a signed OAuth request!",
				"include_entities":       "true",
				"oauth_consumer_key":     "xvz1evFS4wEEPTGEFPHBog",
				"oauth_nonce":            "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
				"oauth_signature_method": "HMAC-SHA1",
				"oauth_timestamp":        "1318622958",
				"oauth_token":            "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
				"oauth_version":          "1.0",
			}, "tnnArxj06cWHq44gCs1OSKk/jLY="},
	}
	for _, testCase := range golden {
		actual := GetSignature(testCase.cs, testCase.ts,
			testCase.method, testCase.url, testCase.params)
		if testCase.expected != actual {
			t.Errorf("input:%s, actual:%s, expected:%s", testCase, actual, testCase.expected)
		}
	}
}

func TestGetParameterString(t *testing.T) {
	type TestCase struct {
		params   map[string]string
		expected string
	}
	golden := []TestCase{
		TestCase{
			map[string]string{
				"b": "123",
				"a": "Hello World",
				"z": "xxx",
			}, "a=Hello%20World&b=123&z=xxx"},
	}
	for _, testCase := range golden {
		actual := getParameterString(testCase.params)
		if testCase.expected != actual {
			t.Errorf("input:%s, actual:%s, expected:%s", testCase, actual, testCase.expected)
		}
	}
}

func TestPercentEncode(t *testing.T) {
	golden := map[string]string{
		"Ladies + Gentlemen": "Ladies%20%2B%20Gentlemen",
		"An encoded string!": "An%20encoded%20string%21",
		"Dogs, Cats & Mice":  "Dogs%2C%20Cats%20%26%20Mice",
		"☃":                  "%E2%98%83",
	}

	for input, expected := range golden {
		actual := percentEncode(input)
		if expected != actual {
			t.Errorf("input:%s, actual:%s, expected:%s", input, actual, expected)
		}
	}
}

func TestGetSigningKey(t *testing.T) {
	type TestCase struct {
		cs       string
		ts       string
		expected string
	}
	golden := []TestCase{
		TestCase{"ConsumerSecret", "TokenSecret", "ConsumerSecret&TokenSecret"},
		TestCase{"C S", "T S", "C%20S&T%20S"},
	}
	for _, testCase := range golden {
		actual := getSigningKey(testCase.cs, testCase.ts)
		if testCase.expected != actual {
			t.Errorf("input:%s, actual:%s, expected:%s", testCase, actual,
				testCase.expected)
		}
	}
}

func TestGetSignatureBaseString(t *testing.T) {
	type TestCase struct {
		method   string
		url      string
		params   string
		expected string
	}
	golden := []TestCase{
		TestCase{
			"post", "http://www.gant.net",
			"msg=Hello%20World&id=123",
			"POST&http%3A%2F%2Fwww.gant.net&msg%3DHello%2520World%26id%3D123",
		},
	}
	for _, testCase := range golden {
		actual := getSignatureBaseString(testCase.method, testCase.url,
			testCase.params)
		if testCase.expected != actual {
			t.Errorf("input:%s, actual:%s, expected:%s", testCase, actual,
				testCase.expected)
		}
	}
}
