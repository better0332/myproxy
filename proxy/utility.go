package proxy

import (
	"bitbucket.org/better0332/WebHunter/proxy/cacheLayer"
	"bitbucket.org/better0332/WebHunter/proxy/db"
	"bitbucket.org/better0332/WebHunter/queue"
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
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

func InitCA() error {
	var err error

	cert := "Fake-ACRoot-Certificate.cer"
	key := "Fake-ACRoot-Key.pem"

	if RootCert, err = tls.LoadX509KeyPair(cert, key); err != nil {
		return err
	}
	if X509RootCert, err = x509.ParseCertificate(RootCert.Certificate[0]); err != nil {
		return err
	}

	return nil
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

/*func RespFrontend(writer io.Writer, resp *http.Response) {
	// todo: use bufio.Writer
	io.WriteString(writer, resp.Proto+" "+resp.Status+"\r\n")
	resp.Header.Write(writer)
	io.WriteString(writer, "\r\n")
	io.Copy(writer, resp.Body)
	io.WriteString(writer, "\r\n")
}

func ReqBackend(writer io.Writer, req *http.Request) {
	// todo: use bufio.Writer
	var path string
	if req.URL.Opaque != "" {
		path = req.URL.Opaque
	} else {
		path = req.URL.Path
	}
	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}
	io.WriteString(writer, req.Method+" "+path+" "+req.Proto+"\r\n")
	io.WriteString(writer, "Host: "+req.Host+"\r\n")
	req.Header.Write(writer)
	io.WriteString(writer, "\r\n")
	io.Copy(writer, req.Body)
	io.WriteString(writer, "\r\n")
}*/

func FixRequest(req *http.Request) {
	// issue: https://code.google.com/p/go/issues/detail?id=6784 in shipin7.com
	if strings.Contains(req.URL.Path, "!") {
		req.URL.Opaque = "//" + req.URL.Host + req.URL.Path
	}
}

func FixResponse(resp *http.Response) {
	// https://code.google.com/p/go/issues/detail?id=5381
	// fix add Content-Length: 0 when resp.Write()
	if resp != nil && resp.StatusCode == 200 &&
		resp.ContentLength == 0 && len(resp.TransferEncoding) == 0 {
		resp.TransferEncoding = append(resp.TransferEncoding, "identity")
	}
}

func TLSConfig(host string, dnsNames []string) (*tls.Config, error) {
	cfg := new(tls.Config)
	if strings.IndexRune(host, ':') > -1 {
		host = strings.Split(host, ":")[0]
	}
	cert, err := getTLSCert(host, dnsNames)
	if nil != err {
		log.Printf("Failed to get tls cert: %s\n", err)
		return nil, err
	}
	cfg.Certificates = []tls.Certificate{*cert}
	// cfg.Certificates = []tls.Certificate{*cert, RootCert}
	// cfg.BuildNameToCertificate()
	return cfg, nil
}

func getTLSCert(host string, dnsNames []string) (tlsCert *tls.Certificate, err error) {
	host = strings.ToLower(host)

	cachedCertificates.RLock()
	if tlsCert, exist := cachedCertificates.m[host]; exist {
		cachedCertificates.RUnlock()
		return tlsCert, nil
	}
	cachedCertificates.RUnlock()

	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Println(err)
		return
	}
	keyId := make([]byte, 20)
	rand.Read(keyId)

	serial, _ := rand.Int(rand.Reader, big.NewInt(0x7FFFFFFFFFFFFFFF))

	template := x509.Certificate{
		Subject:        pkix.Name{CommonName: host},
		Issuer:         X509RootCert.Issuer,
		SerialNumber:   serial,
		SubjectKeyId:   keyId,
		AuthorityKeyId: X509RootCert.AuthorityKeyId,
		NotBefore:      time.Now().AddDate(-2, 0, 0).UTC(),
		NotAfter:       time.Now().AddDate(12, 0, 0).UTC(),
		DNSNames:       dnsNames,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, X509RootCert,
		&priv.PublicKey, RootCert.PrivateKey)
	if err != nil {
		log.Println(err)
		return
	}

	tlsCert = &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
	cachedCertificates.RLock()
	cachedCertificates.m[host] = tlsCert
	cachedCertificates.RUnlock()

	return
}

func DrainBody(b io.ReadCloser) (r1, r2 io.ReadCloser, err error) {
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(b); err != nil {
		return nil, nil, err
	}
	if err = b.Close(); err != nil {
		return nil, nil, err
	}
	return ioutil.NopCloser(&buf), ioutil.NopCloser(bytes.NewBuffer(buf.Bytes())), nil
}

func MyEncode(s string) string {
	hexCount := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '&', '=':
			hexCount++
		}
	}
	if hexCount == 0 {
		return s
	}

	t := make([]byte, len(s)+2*hexCount)
	for i, j := 0, 0; i < len(s); i++ {
		switch s[i] {
		case '&':
			t[j] = '%'
			t[j+1] = '2'
			t[j+2] = '6'
			j += 3
		case '=':
			t[j] = '%'
			t[j+1] = '3'
			t[j+2] = 'D'
			j += 3
		default:
			t[j] = s[i]
			j++
		}
	}
	return string(t)
}

func InsertHttpInfo(info *httpInfo) {
	req := info.req
	body := info.body

	if info.acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", info.acceptEncoding)
	}
	req.Body = ioutil.NopCloser(bytes.NewReader(body))

	scheme := req.URL.Scheme
	method := req.Method
	host := strings.ToLower(req.URL.Host)
	domain := getDomain(host)
	path := req.URL.RequestURI()
	reqConLen := req.ContentLength

	var post, fileinfo string
	var reqStream []byte

	if int(req.ContentLength) == len(body) ||
		(req.ContentLength == -1 && len(body) < maxReq) {

		var b bytes.Buffer
		req.Write(&b)
		reqStream = b.Bytes()

		if err := req.ParseMultipartForm(1024 * 500); err != nil {
			log.Println(err)
		}
		if req.PostForm != nil {
			// x-www-form-urlencoded post
			post = req.PostForm.Encode()
		}
		if req.MultipartForm != nil {
			post = url.Values(req.MultipartForm.Value).Encode()
			var file string
			for key, fh := range req.MultipartForm.File {
				f, _ := fh[0].Open()
				size_int64, _ := f.Seek(0, 2)
				f.Close()
				file += MyEncode(key) + "=" + MyEncode(fh[0].Filename) +
					"(" + strconv.Itoa(int(size_int64)) + ")&"
				log.Printf("%s size: %d\n", fh[0].Filename, size_int64)
			}
			if file != "" {
				fileinfo = file[:len(file)-1]
			}
		}

		if reqConLen > 0 && post == "" {
			post = string(body)
		}
	}

	db.Insert(scheme, method, host, domain, path, info.respStatus,
		reqConLen, info.respConLen, post, fileinfo, reqStream)
}

func (proxy *Proxy) proxyHttp(cacheConn *cacheLayer.CacheConn, bConn net.Conn) error {
	rd := bufio.NewReader(cacheConn)
	flag, err := rd.Peek(4)
	if err == nil && (string(flag[:3]) == "GET" || string(flag[:4]) == "POST") {
		if req, err := http.ReadRequest(rd); err == nil {
			req.Body.Close()

			var isHTTPS bool

			cacheConn.Mode = cacheLayer.NoCache
			cacheConn.NoCtrl = true
			if _, ok := bConn.(*tls.Conn); ok {
				isHTTPS = true
			} else {
				cacheConn.SetDeadline(time.Now().Add(2 * time.Hour))
				isHTTPS = false
			}

			type reqAndBody struct {
				req  *http.Request
				body []byte
			}

			quit := make(chan bool, 2)
			reqBodyCh := make(chan *reqAndBody, 50)
			rd := bufio.NewReader(cacheConn)
			brd := bufio.NewReader(bConn)

			go func() {
				defer func() { quit <- true }()

				for {
					req, err := http.ReadRequest(rd)
					if err != nil {
						if err != io.EOF {
							// log.Printf("http.ReadRequest err: %s\n", err)
						}
						break
					}

					if isHTTPS {
						req.URL.Scheme = "https"
					} else {
						req.URL.Scheme = "http"
					}
					req.URL.Host = req.Host
					log.Printf("Got request %s %s\n", req.Method, req.URL)

					var body []byte
					if req.ContentLength != 0 && req.Method == "POST" {
						body, err = ioutil.ReadAll(io.LimitReader(req.Body, maxReq))
						if err != nil {
							log.Printf("Read Request body err: %s\n", err)
							break
						}

						req.Body = &readerAndCloser{io.MultiReader(bytes.NewReader(body), req.Body), req.Body}
					}
					FixRequest(req)
					reqBodyCh <- &reqAndBody{req, body}

					if err = req.Write(bConn); err != nil {
						log.Printf("req.write err: %s\n", err)
						break
					}
				} // for
			}()

			go func() {
				defer func() { quit <- true }()

				for {
					resp, err := http.ReadResponse(brd, nil)
					if err != nil {
						if err != io.EOF {
							// log.Printf("http.ReadResponse err: %s\n", err)
						}
						break
					}
					if resp.StatusCode == 100 {
						// Skip any 100-continue for now.
						// TODO(bradfitz): if rc.req had "Expect: 100-continue",
						// actually block the request body write and signal the
						// writeLoop now to begin sending it. (Issue 2184) For now we
						// eat it, since we're never expecting one.
						resp, err = http.ReadResponse(brd, nil)
					}
					FixResponse(resp)
					reqBody := <-reqBodyCh

					if (resp.StatusCode == 200 && resp.Header.Get("ETag") == "" &&
						resp.Header.Get("Last-Modified") == "") ||
						resp.Header.Get("Location") != "" {
						if pushUrl(reqBody.req.URL.String()) {
							go InsertHttpInfo(&httpInfo{reqBody.req, resp.StatusCode,
								resp.ContentLength, reqBody.body, ""})
						}
					}

					if err = resp.Write(cacheConn); err != nil {
						log.Printf("resp.write err: %s\n", err)
						break
					}
				} // for
			}()

			<-quit // wait for either side to close

			return nil
		}
	}
	return errors.New("go on")
}

func (proxy *Proxy) proxyHttps(cacheConn *cacheLayer.CacheConn, bConn net.Conn) error {
	clientTls := tls.Server(cacheConn, &tls.Config{})
	if err := clientTls.Handshake(); strings.Contains(err.Error(), "internal error") {
		// it means can handshake
		tlsBconn := tls.Client(bConn, &tls.Config{InsecureSkipVerify: true})
		defer tlsBconn.Close()

		if err := tlsBconn.Handshake(); err != nil {
			log.Printf("Handshake to %s: %v\n", proxy.Target, err)
			return errors.New("go on")
		}

		var dnsNames []string
		if proxy.Domain == "" {
			proxy.Domain = reflect.ValueOf(clientTls).Elem().FieldByName("serverName").String()
			if proxy.Domain == "" {
				cstate := tlsBconn.ConnectionState()
				proxy.Domain = cstate.PeerCertificates[0].Subject.CommonName
				dnsNames = cstate.PeerCertificates[0].DNSNames
			}
		}
		tlsCfg, err := TLSConfig(proxy.Domain, dnsNames)
		if err != nil {
			log.Printf("%s\n", err)
			return errors.New("go on")
		}

		cacheConn.Mode = cacheLayer.NoCache
		cacheConn.NoCtrl = true
		cacheConn.SetDeadline(time.Now().Add(2 * time.Hour))

		clientTls = tls.Server(cacheConn, tlsCfg)
		if err := clientTls.Handshake(); err != nil {
			log.Printf("Cannot handshake client %s %v\n", proxy.Target, err)
			panic(nil)
		}
		defer clientTls.Close()

		cacheClientTls := cacheLayer.NewCacheConn(clientTls)
		if proxy.proxyHttp(cacheClientTls, tlsBconn) != nil {
			proxy.iobridge(tlsBconn, cacheClientTls)
		}
		return nil
	}
	return errors.New("go on")
}

func (proxy *Proxy) proxying() {
	cacheConn := cacheLayer.NewCacheConn(proxy.Conn)

	if proxy.proxyHttp(cacheConn, proxy.Bconn) == nil {
		return
	}
	cacheConn.Ptr = 0

	if proxy.proxyHttps(cacheConn, proxy.Bconn) == nil {
		return
	}
	cacheConn.Ptr = 0

	cacheConn.Mode = cacheLayer.NoCache
	cacheConn.NoCtrl = true
	cacheConn.SetDeadline(time.Now().Add(2 * time.Hour))

	proxy.iobridge(proxy.Bconn, cacheConn)

}

func (proxy *Proxy) iobridge(dst, src io.ReadWriter) {
	quit := make(chan bool, 2)

	go func() {
		defer func() { quit <- true }()

		io.Copy(dst, src)
	}()
	go func() {
		defer func() { quit <- true }()

		io.Copy(src, dst)
	}()

	<-quit // wait for either side to close
}
