package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type HttpsProxy struct {
	Proxy
	Req *http.Request
}

func (hs *HttpsProxy) HandleHttps() {
	resp := Basic(hs.Req, "WebHunter")
	if resp != nil {
		defer resp.Body.Close()

		// RespFrontend(hs.Conn, resp)
		resp.Write(hs.Conn)
		return
	}
	hs.Target = hs.Req.URL.Host

	log.Printf("CONNECT to %s\n", hs.Target)
	hs.Conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))

	tlsCfg, err := TLSConfig(hs.Target, nil)
	if err != nil {
		log.Printf("%s\n", err)
		return
	}
	clientTls := tls.Server(hs.Conn, tlsCfg)
	if err := clientTls.Handshake(); err != nil {
		log.Printf("Cannot handshake client %s %s\n", hs.Target, err)
		return
	}

	log.Printf("ServerName: %s\n", clientTls.ConnectionState().ServerName)

	defer clientTls.Close()
	clientTlsReader := bufio.NewReader(clientTls)

	req, err := http.ReadRequest(clientTlsReader)
	if err != nil {
		log.Println(err)
		return
	}

	req.URL.Scheme = "https"
	req.URL.Host = hs.Target
	req.RequestURI = ""
	// If no Accept-Encoding header exists, Transport will add the headers it can accept
	// and would wrap the response body with the relevant reader.
	acceptEncoding := req.Header.Get("Accept-Encoding")
	if acceptEncoding != "" {
		req.Header.Del("Accept-Encoding")
	}
	url := req.URL.String()
	log.Printf("Got request %s %s\n", req.Method, url)

	var body []byte
	if req.ContentLength != 0 && req.Method == "POST" {
		body, err = ioutil.ReadAll(io.LimitReader(req.Body, maxReq))
		if err != nil {
			log.Printf("Read Request body err: %s\n", err)
			return
		}

		req.Body = &readerAndCloser{io.MultiReader(bytes.NewReader(body), req.Body), req.Body}
	}

	FixRequest(req)
	if resp, err = client.Do(req); err != nil &&
		strings.Index(err.Error(), forbiddenRedirect) == -1 {
		log.Printf("client.Do err: %s\n", err)
		return
	}
	FixResponse(resp)

	if (resp.StatusCode == 200 && resp.Header.Get("ETag") == "" &&
		resp.Header.Get("Last-Modified") == "") ||
		resp.Header.Get("Location") != "" {
		if pushUrl(url) {
			go InsertHttpInfo(&httpInfo{req, resp.StatusCode, resp.ContentLength,
				body, acceptEncoding})
		}
	}

	resp.Write(clientTls)
}
