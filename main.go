package main

import (
	"flag"
	"io"
	"log"
	"fmt"
	"github.com/nkuln/tgrep/auth"
	"github.com/nkuln/tgrep/twitter"
	"net/http"
	"encoding/json"
)

var lang = flag.String("lang", "th-th", "language to grep data from")
var consumerKey = flag.String("conskey", "", "oauth consumer key")
var consumerSecret = flag.String("conssecret", "", "oauth consumer secret")
var tokenSecret = flag.String("tokensecret", "", "oauth token secret")
var accessToken = flag.String("accesstoken", "", "oauth access token")

func main() {
	flag.Parse()
	req, err := auth.MakeAuthorizedRequest(*consumerKey, *consumerSecret,
		*tokenSecret, *accessToken,
		"POST", "https://stream.twitter.com/1.1/statuses/filter.json",
		map[string]string{
			"track": "ครับ",
			// "locations": "97.97,5.25,105.65,20.35",
		})
	if err != nil {
		fmt.Println("Error!", err)
		return
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error!", err)
		return
	}
	if resp.StatusCode != 200 {
		log.Fatal("Invalid response: ", resp.Status);
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var m twitter.Tweets
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err, dec)
		}
		fmt.Printf("%s : %s / %s\n", m.Created_at, m.Text, m.User.Name)
	}
}
