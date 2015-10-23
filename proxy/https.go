package proxy

import (
	"log"
	"net"
	"net/http"
	"time"
)

type HttpsProxy struct {
	Proxy
	Req *http.Request
}

func (hs *HttpsProxy) HandleHttps() {
	resp := Basic(hs.Req, "myproxy")
	if resp != nil {
		defer resp.Body.Close()

		// RespFrontend(hs.Conn, resp)
		resp.Write(hs.Conn)
		return
	}
	hs.Target = hs.Req.URL.Host

	log.Printf("CONNECT to %s\n", hs.Target)

	bconn, err := net.Dial("tcp", hs.Target)
	if err != nil {
		log.Printf("failed to connect to %s: %s\n", hs.Target, err)
		return
	}
	hs.Bconn = bconn
	hs.Conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))

	remoteaddr := hs.Bconn.RemoteAddr().String()
	log.Printf("connected to backend %s\n", remoteaddr)

	defer func() {
		hs.Bconn.Close()
		log.Printf("disconnected from backend %s\n", remoteaddr)
	}()

	// reset deadline
	// hs.Conn.SetDeadline(time.Now().Add(2 * time.Hour))
	hs.Bconn.SetDeadline(time.Now().Add(2 * time.Minute))

	// proxying
	hs.proxying()
}
