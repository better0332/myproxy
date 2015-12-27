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

	account  = accountMap{m: make(map[string]*accountInfo, 200)}
	relayMap = relayServerMap{m: make(map[string][]net.IP, 16)}

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

type relayServerMap struct {
	m map[string][]net.IP
	l sync.RWMutex
}

func GetRelayMapIPS(relayServer string) []net.IP {
	relayMap.l.RLock()
	defer relayMap.l.RUnlock()

	return relayMap.m[relayServer]
}

func SetRelayMap(relayServer string) error {
	ips, err := net.LookupIP(relayServer)
	if err != nil {
		return err
	}
	relayMap.l.Lock()
	relayMap.m[relayServer] = ips
	relayMap.l.Unlock()

	return nil
}

func ParseRelay() {
	tmp := relayServerMap{m: make(map[string][]net.IP, 16)}

	relayMap.l.RLock()
	for k, _ := range relayMap.m {
		tmp.m[k] = nil
	}
	relayMap.l.RUnlock()

	for k, _ := range tmp.m {
		if ips, err := net.LookupIP(k); err == nil {
			tmp.m[k] = ips
		}
	}

	relayMap.l.Lock()
	for k, v := range tmp.m {
		relayMap.m[k] = v
	}
	relayMap.l.Unlock()
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

			f := float64(info.duration) / float64(tCycle)
			//log.Println(f)
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

type SockAddr struct {
	Host string
	Port int
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
	for _, ip := range GetRelayMapIPS(proxy.Info.relayServer) {
		if bytes.Equal(remoteIP, ip) {
			return true
		}
	}
	return false
}

func (proxy *Proxy) resetDeadline() {
	if proxy.TcpPort == 80 || proxy.TcpPort == 443 {
		proxy.Conn.SetDeadline(time.Now().Add(5 * time.Second))
		proxy.Bconn.SetDeadline(time.Now().Add(5 * time.Second))
	} else {
		proxy.Conn.SetDeadline(time.Now().Add(30 * time.Second))
		proxy.Bconn.SetDeadline(time.Now().Add(30 * time.Second))
	}
}

func (proxy *Proxy) upTransferTcp(sum int64) {
	atomic.AddInt64(&proxy.Info.Transfer, sum)
	if proxy.Info.logEnable && *proxy.TcpId > 0 {
		if len(CacheChan) < cap(CacheChan) {
			CacheChan <- &UpdateTcpST{*proxy.TcpId, sum}
		} else {
			log.Printf("[%s][UpdateTcpST]CacheChan is full drop tcpid %d\n", proxy.User, proxy.TcpId)
		}
	}
}

func (proxy *Proxy) proxying() {
	proxy.Quit = make(chan bool, 2)

	go func() {
		defer func() { proxy.Quit <- true }()

		for {
			proxy.resetDeadline() // 由于io.CopyN的特性,跳出for循环超时时间为指定默认超时的倍数
			n, err := io.CopyN(proxy.Bconn, proxy.Conn, 256<<10)
			if n > 0 {
				proxy.upTransferTcp(n)
			}
			if err != nil {
				if !isTimeoutConn(err) || n == 0 {
					break
				}
			}
		}
	}()
	go func() {
		defer func() { proxy.Quit <- true }()

		for {
			proxy.resetDeadline() // 由于io.CopyN的特性,跳出for循环超时时间为指定默认超时的倍数
			n, err := io.CopyN(proxy.Conn, proxy.Bconn, 256<<10)
			if n > 0 {
				proxy.upTransferTcp(n)
			}
			if err != nil {
				if !isTimeoutConn(err) || n == 0 {
					break
				}
			}
		}
	}()

	<-proxy.Quit // wait for either side to close
}
