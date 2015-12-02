package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

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

	blockdomain = []string{
		"baidu.com",
		"qq.com",
		"163.com",
		"youku.com",
		"iqiyi.com",
		"sohu.com",
		"weibo.com",
		"bilibili.com",
		"acfun.tv",
		"hunantv.com",
		"letv.com",
		"cntv.cn",
		"taobao.com",
		"jd.com",
		"tmall.com",
		"sina.com.cn",
		"onlinedown.net",
		"skycn.com",
		"xunlei.com",
		"verycd.com",
		"kugou.com",
		"tudou.com",
		"pptv.com",
		"kankan.com",
		"360.com",
		"360.cn",
		"360safe.com",
		"58.com",
		"ganji.com",
		"proxycap.com",
		"localhost",
	}

	account = accountMap{m: make(map[string]*accountInfo, 200)}

	UdpRelayIpNet *net.IPNet
)

type Proxy struct {
	Conn        net.Conn
	ConnBufRead *bufio.Reader
	Bconn       net.Conn

	User string
	Info *accountInfo

	Target  string
	Domain  string
	TcpPort uint

	tcpId int64

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

type accountInfo struct {
	pwd         string
	logEnable   bool
	relayEnable bool

	transfer int64
}

type accountMap struct {
	m map[string]*accountInfo
	l sync.RWMutex
}

func GetAccountTrans() map[string]int64 {
	trans := make(map[string]int64, 200)

	account.l.RLock()
	for user, info := range account.m {
		if v := atomic.LoadInt64(&info.transfer); v > 0 {
			trans[user] = v
			atomic.StoreInt64(&info.transfer, 0)
		}
	}
	account.l.RUnlock()

	return trans
}

func GetAccountInfo(user string) *accountInfo {
	account.l.RLock()
	defer account.l.RUnlock()

	info, _ := account.m[user]
	return info
}

func SetAccount(user, pwd string, logEnable, relayEnable bool) {
	account.l.Lock()
	defer account.l.Unlock()

	account.m[user] = &accountInfo{pwd, logEnable, relayEnable, 0}
}

func DelAccount(user string) {
	account.l.Lock()
	defer account.l.Unlock()

	delete(account.m, user)
}

func InitAccountMap(host string) {
	SetAccountMap(account.m, host)
}

func isBlockDomain(domain string) bool {
	for i := 0; i < len(blockdomain); i++ {
		if strings.HasSuffix(domain, blockdomain[i]) {
			return true
		}
	}
	return false
}

func isBlockIP(ip string) bool {
	return strings.HasPrefix(ip, "127.") ||
		strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "172.16.") ||
		strings.HasPrefix(ip, "0.") ||
		strings.HasPrefix(ip, "255.")
}

func isBlockPort(port uint) bool {
	return port == 3077 || port == 3076 ||
		port == 7777 || port == 7778 || port == 11300 ||
		port == 4662 || port == 4661 || port == 4242 || port == 4371
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
	host, portstr, err := net.SplitHostPort(HostPort)
	if err != nil {
		panic(err)
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		panic(err)
	}
	return SockAddr{host, port}
}

func (addr *SockAddr) String() string {
	return net.JoinHostPort(addr.Host, strconv.Itoa(addr.Port))
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

		var total int64
		for {
			n, err := io.CopyN(dst, src, 64<<10)
			if n > 0 && proxy.Info.logEnable {
				total += n
				if len(CacheChan) < cap(CacheChan) {
					CacheChan <- &UpdateTcpST{proxy.tcpId, n}
				} else {
					log.Printf("[%s]CacheChan is full drop tcpid %d\n", proxy.User, proxy.tcpId)
				}
			}
			if err != nil {
				break
			}
		}
		atomic.AddInt64(&proxy.Info.transfer, total)
	}()
	go func() {
		defer func() { proxy.Quit <- true }()

		var total int64
		for {
			n, err := io.CopyN(src, dst, 64<<10)
			if n > 0 && proxy.Info.logEnable {
				total += n
				if len(CacheChan) < cap(CacheChan) {
					CacheChan <- &UpdateTcpST{proxy.tcpId, n}
				} else {
					log.Printf("[%s]CacheChan is full drop tcpid %d\n", proxy.User, proxy.tcpId)
				}
			}
			if err != nil {
				break
			}
		}
		atomic.AddInt64(&proxy.Info.transfer, total)
	}()

	<-proxy.Quit // wait for either side to close
}
