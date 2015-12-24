package proxy

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net"
	"os"
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
	blockdomain []string

	threshold uint
	blockTime uint
	ratio     float64

	account = accountMap{m: make(map[string]*accountInfo, 200)}

	udpRelayIpNets []*net.IPNet
)

func SetBlockDomain(f string) error {
	file, err := os.Open(f)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		blockdomain = append(blockdomain, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Printf("%s is not full load: %v", f, err)
	}
	return nil
}

func SetConcurrentcy(t, b uint, r float64) {
	threshold, blockTime, ratio = t, b, r
}

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

	User       string
	Info       *accountInfo
	CoCheck    bool
	RelayCheck bool

	Target  string
	Domain  string
	TcpPort uint

	TcpId *int64 //race detect

	Quit chan bool
}

type SockAddr struct {
	Host string
	Port int
}

type accountInfo struct {
	User        string
	pwd         string
	relayServer []net.IP
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

			f := float64(info.duration) / float64(tCycle)
			log.Println(f)
			if f > ratio {
				info.timeAbnormal = time.Now().Unix()
				log.Printf("[%s]concurrency overhead!\n", info.User)
				index := uint(len(info.connMap)) - threshold
				for conn, _ := range info.connMap {
					if index <= 0 {
						break
					}
					conn.Close()
					index--
				}
			} else if info.timePoint > 0 {
				info.timePoint = time.Now().UnixNano()
				info.duration = 0
			} else {
				info.duration = 0
			}
		} else if uint(time.Now().Unix()-info.timeAbnormal) > blockTime*60 {
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

func SetAccount(user, pwd string, relayServer []net.IP, logEnable bool) {
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

func isTimeoutConn(err error) bool {
	operr, ok := err.(*net.OpError)
	return ok && operr.Timeout()
}

func protocolCheck(assert bool) {
	if !assert {
		panic("protocol error")
	}
}

func (proxy *Proxy) concurrencyCheck() bool {
	info := proxy.Info

	info.protect.Lock()
	defer info.protect.Unlock()

	if len(info.connMap) >= 100 {
		log.Printf("[%s]concurrency more than 100\n", proxy.User)
		return false
	}
	if info.timeAbnormal > 0 && uint(len(info.connMap)) >= threshold {
		log.Printf("[%s]abnormal concurrency more than %d\n", proxy.User, threshold)
		return false
	}
	info.connMap[proxy.Conn] = 1

	if info.timeAbnormal == 0 && info.timePoint == 0 && uint(len(info.connMap)) > threshold {
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
		if info.timeAbnormal == 0 && info.timePoint > 0 && uint(len(info.connMap)) <= threshold {
			info.duration += time.Now().UnixNano() - info.timePoint
			info.timePoint = 0
		}
		info.protect.Unlock()
	}
}

func (proxy *Proxy) relayCheck(remoteIP net.IP) bool {
	for _, ip := range proxy.Info.relayServer {
		if bytes.Equal(remoteIP, ip) {
			return true
		}
	}
	return false
}

func (proxy *Proxy) resetDeadline() {
	if proxy.TcpPort == 80 && proxy.TcpPort == 443 {
		proxy.Conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		proxy.Bconn.SetReadDeadline(time.Now().Add(10 * time.Second))
	} else {
		proxy.Conn.SetReadDeadline(time.Now().Add(1 * time.Minute))
		proxy.Bconn.SetReadDeadline(time.Now().Add(1 * time.Minute))
	}
}

func (proxy *Proxy) proxying() {
	proxy.Quit = make(chan bool, 2)

	go func() {
		defer func() { proxy.Quit <- true }()

		for {
			proxy.resetDeadline()
			n, err := io.CopyN(proxy.Bconn, proxy.Conn, 64<<10)
			if n > 0 {
				atomic.AddInt64(&proxy.Info.Transfer, n)
				if proxy.Info.logEnable && *proxy.TcpId > 0 {
					if len(CacheChan) < cap(CacheChan) {
						CacheChan <- &UpdateTcpST{*proxy.TcpId, n}
					} else {
						log.Printf("[%s][UpdateTcpST]CacheChan is full drop tcpid %d\n", proxy.User, proxy.TcpId)
					}
				}
			}
			if err != nil {
				if isTimeoutConn(err) && n == 0 || !isTimeoutConn(err) {
					break
				}
			}
		}
	}()
	go func() {
		defer func() { proxy.Quit <- true }()

		for {
			proxy.resetDeadline()
			n, err := io.CopyN(proxy.Conn, proxy.Bconn, 64<<10)
			if n > 0 {
				atomic.AddInt64(&proxy.Info.Transfer, n)
				if proxy.Info.logEnable && *proxy.TcpId > 0 {
					if len(CacheChan) < cap(CacheChan) {
						CacheChan <- &UpdateTcpST{*proxy.TcpId, n}
					} else {
						log.Printf("[%s][UpdateTcpST]CacheChan is full drop tcpid %d\n", proxy.User, proxy.TcpId)
					}
				}
			}
			if err != nil {
				if isTimeoutConn(err) && n == 0 || !isTimeoutConn(err) {
					break
				}
			}
		}
	}()

	<-proxy.Quit // wait for either side to close
}
