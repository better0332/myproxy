package proxy

import (
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxReq = 1024 * 1024 * 2
)

var (
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

	udpRelayIpNets []*net.IPNet
)

func AppendIpNets(ipnet *net.IPNet) {
	udpRelayIpNets = append(udpRelayIpNets, ipnet)
}

func IsIpContains(ip net.IP) bool {
	for _, ipnet := range udpRelayIpNets {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

type Proxy struct {
	Conn  net.Conn
	Bconn net.Conn

	User    string
	Info    *accountInfo
	CoCheck bool

	Target  string
	Domain  string
	TcpPort uint

	TcpId *int64

	Quit chan bool
}

type SockAddr struct {
	Host string
	Port int
}

type accountInfo struct {
	User        string
	pwd         string
	relayServer string
	logEnable   bool

	Transfer int64 //protect by sync/atomic

	protect      sync.Mutex
	timeAbnormal int64 //unix
	timePoint    int64 //UnixNano
	duration     int64
	connMap      map[net.Conn]int
}

type accountMap struct {
	m map[string]*accountInfo
	l sync.RWMutex
}

func HandleAccountInfo(tCycle int64) []*accountInfo {
	infoArray := make([]*accountInfo, 0, 200)

	account.l.RLock()
	for _, info := range account.m {
		infoArray = append(infoArray, info)
	}
	account.l.RUnlock()

	for _, info := range infoArray {
		info.protect.Lock()

		if info.timeAbnormal == 0 {
			if info.timePoint > 0 {
				info.duration = time.Now().UnixNano() - info.timePoint
			}

			if float32(info.duration)/float32(tCycle) > 0.8 {
				info.timeAbnormal = time.Now().Unix()
				index := len(info.connMap) - 10
				for conn, _ := range info.connMap {
					if index == 0 {
						break
					}
					conn.Close()
					index--
				}
				log.Printf("[%s]concurrency overhead!\n", info.User)
			} else if info.timePoint > 0 {
				info.timePoint = time.Now().UnixNano()
				info.duration = 0
			} else {
				info.duration = 0
			}
		} else if time.Now().Unix()-info.timeAbnormal > 2*3600 {
			info.timeAbnormal = 0
			info.timePoint = 0
			info.duration = 0
			log.Printf("[%s]abnormal concurrency recover!\n", info.User)
		}

		info.protect.Unlock()
	}

	return infoArray
}

func GetAccountInfo(user string) *accountInfo {
	account.l.RLock()
	defer account.l.RUnlock()

	info, _ := account.m[user]
	return info
}

func SetAccount(user, pwd, relayServer string, logEnable bool) {
	info := &accountInfo{
		User:        user,
		pwd:         pwd,
		relayServer: relayServer,
		logEnable:   logEnable,
		connMap:     make(map[net.Conn]int, 10),
	}

	account.l.Lock()
	if v, ok := account.m[user]; ok {
		delete(account.m, user)
		account.l.Unlock()

		v.protect.Lock()
		for conn, _ := range v.connMap {
			conn.Close()
		}
		v.protect.Unlock()

		account.l.Lock()
	}
	account.m[user] = info
	account.l.Unlock()
}

func DelAccount(user string) {
	account.l.Lock()
	if v, ok := account.m[user]; ok {
		delete(account.m, user)
		account.l.Unlock()

		v.protect.Lock()
		for conn, _ := range v.connMap {
			conn.Close()
		}
		v.protect.Unlock()

		return
	}
	account.l.Unlock()
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

func readBytes(rd io.Reader, count int) (buf []byte) {
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

func (proxy *Proxy) setTcpId(id int64) {
	atomic.StoreInt64(proxy.TcpId, id)
}

func (proxy *Proxy) getTcpId() int64 {
	return atomic.LoadInt64(proxy.TcpId)
}

func (proxy *Proxy) concurrencyCheck() bool {
	info := proxy.Info

	info.protect.Lock()
	defer info.protect.Unlock()

	if len(info.connMap) >= 100 {
		log.Printf("[%s]concurrency more than 100\n", proxy.User)
		return false
	}
	if info.timeAbnormal > 0 && len(info.connMap) >= 10 {
		log.Printf("[%s]abnormal concurrency more than 10\n", proxy.User)
		return false
	}
	info.connMap[proxy.Conn] = 1

	if info.timeAbnormal == 0 && info.timePoint == 0 && len(info.connMap) > 10 {
		info.timePoint = time.Now().UnixNano()
	}

	proxy.CoCheck = true
	return true
}

func (proxy *Proxy) freeConn() {
	if proxy.CoCheck {
		info := proxy.Info

		info.protect.Lock()
		delete(info.connMap, proxy.Conn)
		if info.timeAbnormal == 0 && info.timePoint > 0 && len(info.connMap) <= 10 {
			info.duration += time.Now().UnixNano() - info.timePoint
			info.timePoint = 0
		}
		info.protect.Unlock()
	}
}

func (proxy *Proxy) proxying() {
	proxy.iobridge(proxy.Bconn, proxy.Conn)
}

func (proxy *Proxy) iobridge(dst, src io.ReadWriter) {
	proxy.Quit = make(chan bool, 2)

	go func() {
		defer func() { proxy.Quit <- true }()

		for {
			n, err := io.CopyN(dst, src, 64<<10)
			if n > 0 {
				atomic.AddInt64(&proxy.Info.Transfer, n)
				if proxy.Info.logEnable {
					if id := proxy.getTcpId(); id > 0 && len(CacheChan) < cap(CacheChan) {
						CacheChan <- &UpdateTcpST{id, n}
					} else {
						log.Printf("[%s][UpdateTcpST]CacheChan is full drop tcpid %d\n", proxy.User, id)
					}
				}
			}
			if err != nil {
				break
			}
		}
	}()
	go func() {
		defer func() { proxy.Quit <- true }()

		for {
			n, err := io.CopyN(src, dst, 64<<10)
			if n > 0 {
				atomic.AddInt64(&proxy.Info.Transfer, n)
				if proxy.Info.logEnable {
					if id := proxy.getTcpId(); id > 0 && len(CacheChan) < cap(CacheChan) {
						CacheChan <- &UpdateTcpST{id, n}
					} else {
						log.Printf("[%s][UpdateTcpST]CacheChan is full drop tcpid %d\n", proxy.User, id)
					}
				}
			}
			if err != nil {
				break
			}
		}
	}()

	<-proxy.Quit // wait for either side to close
}
