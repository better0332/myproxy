package main

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/better0332/myproxy/proxy"
)

var (
	server       = flag.String("server", ":443", "server listen address")
	hostname     = flag.String("host", "", "server hostname, default HOSTNAME(1)")
	udpRelayCIDR = flag.String("relay", "", "udp relay CIDR(multi split by comma)")
	blockDomain  = flag.String("blockdomain", "blockdomain.txt", "block domain file")
	threshold    = flag.Uint("threshold", 10, "concurrentcy connection threshold")
	ratio        = flag.Float64("ratio", 0.8, "concurrentcy connection ratio")
	blockTime    = flag.Uint("blocktime", 120, "concurrentcy connection block minutes")

	tr     = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true} /*DisableCompression: true*/}
	client = &http.Client{Transport: tr}
)

func handleConnection(conn net.Conn) {
	clientaddr := proxy.MakeSockAddr(conn.RemoteAddr().String())
	//log.Printf("accepted from frontend %s\n", clientaddr.String())

	var ok bool

	defer func() {
		if err := recover(); err != nil {
			log.Printf("an error occurred with frontend %s: %v\n", clientaddr.String(), err)
		}

		if !ok {
			//log.Printf("disconnected from frontend %s\n", clientaddr.String())
			conn.Close()
		}
	}()

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	socks5 := &proxy.Socks5{}
	socks5.Conn = conn
	ok = socks5.HandleSocks5()
}

func accountSetHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("enter accountSetHandler...")

	user := req.Header.Get("username")
	pwd := req.Header.Get("password")
	logEnable := req.Header.Get("log_enable")
	relayServer := req.Header.Get("relay_server")
	timeStamp := req.Header.Get("timestamp")
	token := req.Header.Get("token")

	stamp, _ := strconv.ParseInt(timeStamp, 10, 0)
	if time.Now().Unix()-stamp > 1800 {
		w.Write([]byte("timestamp is expired!"))
		return
	}
	t := fmt.Sprint("%x", md5.Sum([]byte(user+pwd+logEnable+relayServer+timeStamp+"^_^")))
	if t != token {
		w.Write([]byte("token is invalid!"))
		return
	}

	if user == "" || pwd == "" {
		w.Write([]byte("username or password is empty!"))
		return
	}
	var bLog bool
	if logEnable == "1" {
		bLog = true
	}

	if relayServer != "" {
		var err error
		relayServer, _, err = net.SplitHostPort(relayServer)
		if err != nil {
			w.Write([]byte("relayServer format error!"))
			return
		}
		if err = proxy.SetRelayMap(relayServer); err != nil {
			w.Write([]byte("relayServer fail LookupIP!"))
			return
		}
	}
	proxy.SetAccount(user, pwd, relayServer, bLog)

	w.Write([]byte("ok"))
}

func accountDelHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("enter accountDelHandler...")

	user := req.Header.Get("username")
	timeStamp := req.Header.Get("timestamp")
	token := req.Header.Get("token")

	stamp, _ := strconv.ParseInt(timeStamp, 10, 0)
	if time.Now().Unix()-stamp > 1800 {
		w.Write([]byte("timestamp is expired!"))
		return
	}
	t := fmt.Sprint("%x", md5.Sum([]byte(user+timeStamp+"^_^")))
	if t != token {
		w.Write([]byte("token is invalid!"))
		return
	}

	if user == "" {
		w.Write([]byte("username is empty!"))
		return
	}

	proxy.DelAccount(user)

	w.Write([]byte("ok"))
}

func relayParseHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("enter relayParseHandler...")

	timeStamp := req.Header.Get("timestamp")
	token := req.Header.Get("token")

	stamp, _ := strconv.ParseInt(timeStamp, 10, 0)
	if time.Now().Unix()-stamp > 1800 {
		w.Write([]byte("timestamp is expired!"))
		return
	}
	t := fmt.Sprint("%x", md5.Sum([]byte(timeStamp+"^_^")))
	if t != token {
		w.Write([]byte("token is invalid!"))
		return
	}

	proxy.ParseRelay()

	w.Write([]byte("ok"))
}

func httpServer() {
	http.HandleFunc("/account/set", accountSetHandler)
	http.HandleFunc("/account/del", accountDelHandler)
	http.HandleFunc("/relay/parse", relayParseHandler)

	log.Fatal(http.ListenAndServe(":6061", nil))
}

func cycleHandle() {
	var t1, t2 int64
	t2 = time.Now().UnixNano()

	for {
		time.Sleep(1 * time.Minute)

		t1 = t2
		t2 = time.Now().UnixNano()
		infoArray := proxy.HandleAccountInfo(t2 - t1)

		b, _ := json.Marshal(&infoArray)
		resp, err := client.Post("https://speedmao.com/userinfo", "application/json", bytes.NewReader(b))
		if err != nil {
			log.Println(err)
			continue
		}

		resp.Body.Close()
		if resp.StatusCode == 200 {
			for _, info := range infoArray {
				atomic.SwapInt64(&info.Transfer, 0)
			}
		} else {
			log.Println("post user info fail:", resp.Status)
		}
	}
}

func main() {
	flag.Parse()

	var err error

	if *hostname == "" {
		if *hostname, err = os.Hostname(); err != nil {
			log.Fatal("get os hostname error:", err)
		}
	}

	for _, cidr := range strings.Split(*udpRelayCIDR, ",") {
		if cidr = strings.TrimSpace(cidr); cidr != "" {
			if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
				proxy.AppendIpNets(ipnet)
			} else {
				log.Printf("%s udp relay CIDR format error: %v\n", cidr, err)
			}
		}
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	runtime.GOMAXPROCS(runtime.NumCPU())

	if err = proxy.SetBlockDomain(*blockDomain); err != nil {
		log.Fatal(err)
	}
	proxy.SetConcurrentcy(*threshold, *blockTime, *ratio)
	proxy.InitAccountMap(*hostname)
	log.Println("initAccountMap ok")

	go httpServer()
	go cycleHandle()

	ln, err := net.Listen("tcp", *server)
	if err != nil {
		log.Fatal("Listen error: %s\n", err)
	}
	log.Printf("listening on %s...\n", *server)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %s\n", err)
			continue
		}
		go handleConnection(conn)
	}
}
