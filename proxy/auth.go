package proxy

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"strings"
)

var unauthorizedMsg = []byte("407 Proxy Authentication Required")

func auth(user, pwd string) bool {
	return user == pwd && user != ""
}

func BasicUnauthorized(realm string) *http.Response {
	// TODO: verify realm is well formed
	return &http.Response{
		Status:     "407 Unauthorized",
		StatusCode: 407,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Proxy-Authenticate": []string{"Basic realm=" + realm}},
		Body:       ioutil.NopCloser(bytes.NewBuffer(unauthorizedMsg)),
	}
}

var proxyAuthorizatonHeader = "Proxy-Authorization"

func Basic(req *http.Request, realm string) *http.Response {
	authheader := strings.SplitN(req.Header.Get(proxyAuthorizatonHeader), " ", 2)
	req.Header.Del(proxyAuthorizatonHeader)
	if len(authheader) != 2 || authheader[0] != "Basic" {
		return BasicUnauthorized(realm)
	}
	userpassraw, err := base64.StdEncoding.DecodeString(authheader[1])
	if err != nil {
		return BasicUnauthorized(realm)
	}
	userpass := strings.SplitN(string(userpassraw), ":", 2)
	if len(userpass) != 2 {
		return BasicUnauthorized(realm)
	}
	if !auth(userpass[0], userpass[1]) {
		return BasicUnauthorized(realm)
	}
	return nil
}
