package proxy

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type HttpProxy struct {
	Proxy
	Req *http.Request
}

func (h *HttpProxy) HandleHttp() {
	resp := Basic(h.Req, "WebHunter")
	if resp == nil {
		h.Target = h.Req.URL.Host
		url := h.Req.URL.String()
		log.Printf("Got request %s %s\n", h.Req.Method, url)

		var err error
		h.Req.RequestURI = ""
		h.Req.Header.Del("Proxy-Connection")
		// If no Accept-Encoding header exists, Transport will add the headers it can accept
		// and would wrap the response body with the relevant reader.
		acceptEncoding := h.Req.Header.Get("Accept-Encoding")
		if acceptEncoding != "" {
			h.Req.Header.Del("Accept-Encoding")
		}
		h.Req.Header.Add("X-Forwarded-For", strings.Split(h.Conn.RemoteAddr().String(), ":")[0])

		var body []byte
		if h.Req.ContentLength != 0 && h.Req.Method == "POST" {
			body, err = ioutil.ReadAll(io.LimitReader(h.Req.Body, maxReq))
			if err != nil {
				log.Printf("Read Request body err: %s\n", err)
				return
			}

			h.Req.Body = &readerAndCloser{io.MultiReader(bytes.NewReader(body), h.Req.Body), h.Req.Body}
		}

		FixRequest(h.Req)
		if resp, err = client.Do(h.Req); err != nil &&
			strings.Index(err.Error(), forbiddenRedirect) == -1 {
			log.Printf("client.Do err: %s\n", err)
			return
		}
		FixResponse(resp)

		if (resp.StatusCode == 200 && resp.Header.Get("ETag") == "" &&
			resp.Header.Get("Last-Modified") == "") ||
			resp.Header.Get("Location") != "" {
			if pushUrl(url) {
				go InsertHttpInfo(&httpInfo{h.Req, resp.StatusCode, resp.ContentLength,
					body, acceptEncoding})
			}
		}
	}

	resp.Write(h.Conn)
}
