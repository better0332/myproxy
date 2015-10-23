package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/better0332/myproxy/queue"
)

const (
	maxReq = 1024 * 1024 * 2
)

var (
	tr = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true} /*DisableCompression: true*/}

	client = &http.Client{Transport: tr, CheckRedirect: redirectPolicy}

	RootCert     tls.Certificate
	X509RootCert *x509.Certificate

	cachedCertificates = struct {
		sync.RWMutex
		m map[string]*tls.Certificate
	}{m: make(map[string]*tls.Certificate)}

	urlQueueMap = struct {
		sync.Mutex
		q *queue.Queue
		m map[string]bool
	}{q: queue.NewQueue(5000, false), m: make(map[string]bool, 5000)}

	forbiddenRedirect = "forbidden redirect!"

	reDomain1 = regexp.MustCompile(`[^\.]+\.(?:com|net|org|gov|edu)\.[a-z]{2}$`)
	reDomain2 = regexp.MustCompile(`[^\.]+\.(?:ac|bj|sh|tj|cq|he|sx|nm|ln|jl|hl|js|zj|ah|fj|jx|sd|ha|hb|hn|gd|gx|hi|sc|gz|yn|xz|sn|gs|qh|nx|xj|tw|hk|mo)\.cn$`)
	reDomain3 = regexp.MustCompile(`[^\.]+\.[^\.]+$`)
)

type Proxy struct {
	Conn        net.Conn
	ConnBufRead *bufio.Reader
	Bconn       net.Conn

	Target string
	Domain string

	Quit chan bool
}

type SockAddr struct {
	Host string
	Port int
}

type readerAndCloser struct {
	io.Reader
	io.Closer
}

type httpInfo struct {
	req            *http.Request
	respStatus     int
	respConLen     int64
	body           []byte
	acceptEncoding string
}

func pushUrl(url string) bool {
	if len(url) > 1024 {
		return false
	}
	defer urlQueueMap.Unlock()

	urlQueueMap.Lock()
	if _, ok := urlQueueMap.m[url]; ok {
		return false
	}
	if rUrl := urlQueueMap.q.Push(url); rUrl != nil {
		delete(urlQueueMap.m, rUrl.(string))
	}
	urlQueueMap.m[url] = true
	return true
}

func redirectPolicy(req *http.Request, via []*http.Request) error {
	return errors.New(forbiddenRedirect)
}

// Convert a "host:port" string to SockAddr
func MakeSockAddr(HostPort string) SockAddr {
	pair := strings.Split(HostPort, ":")
	host, portstr := pair[0], pair[1]
	port, err := strconv.Atoi(portstr)
	if err != nil {
		panic(err)
	}
	return SockAddr{host, port}
}

func (addr *SockAddr) String() string {
	return fmt.Sprintf("%s:%d", addr.Host, addr.Port)
}

func (addr *SockAddr) ByteArray() []byte {
	bytes := make([]byte, 6)
	copy(bytes[:4], net.ParseIP(addr.Host).To4())
	bytes[4] = byte(addr.Port >> 8)
	bytes[5] = byte(addr.Port % 256)
	return bytes
}

func readBytes(rd *bufio.Reader, count int) (buf []byte) {
	buf = make([]byte, count)
	if _, err := io.ReadFull(rd, buf); err != nil {
		panic("readBytes err: " + err.Error())
	}
	return
}

func isUseOfClosedConn(err error) bool {
	operr, ok := err.(*net.OpError)
	return ok && operr.Err.Error() == "use of closed network connection"
}

func protocolCheck(assert bool) {
	if !assert {
		panic("protocol error")
	}
}

func getDomain(host string) string {
	host = strings.Split(host, ":")[0]

	if net.ParseIP(host) != nil {
		return host
	}

	var domain string
	if domain = reDomain1.FindString(host); domain != "" {
		return string(domain)
	}
	if domain = reDomain2.FindString(host); domain != "" {
		return string(domain)
	}
	if domain = reDomain3.FindString(host); domain != "" {
		return string(domain)
	}

	return ""
}

func (proxy *Proxy) proxying() {
	proxy.iobridge(proxy.Bconn, proxy.Conn)
}

func (proxy *Proxy) iobridge(dst, src io.ReadWriter) {
	proxy.Quit = make(chan bool, 2)

	go func() {
		defer func() { proxy.Quit <- true }()

		io.Copy(dst, src)
	}()
	go func() {
		defer func() { proxy.Quit <- true }()

		io.Copy(src, dst)
	}()

	<-proxy.Quit // wait for either side to close
}
