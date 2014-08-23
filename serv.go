package main

import (
	"bitbucket.org/better0332/WebHunter/proxy"
	"bufio"
	"flag"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

var (
	profile = flag.Bool("profile", false, "enable pprof")
	port    = flag.Uint("port", 1080, "listen port")
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	if err := os.Chdir(filepath.Dir(os.Args[0])); err != nil {
		log.Fatalln(err)
	}
	if err := proxy.InitCA(); err != nil {
		log.Fatalln("Failed to init root cert: ", err)
	}
}

func handleConnection(conn net.Conn) {
	clientaddr := proxy.MakeSockAddr(conn.RemoteAddr().String())
	log.Printf("accepted from frontend %s\n", clientaddr.String())

	defer func() {
		if err := recover(); err != nil {
			log.Printf("an error occurred with frontend %s: %v\n",
				clientaddr.String(), err)
		}

		conn.Close()
		log.Printf("disconnected from frontend %s\n", clientaddr.String())
	}()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	connBufRead := bufio.NewReader(conn)

	flag, err := connBufRead.Peek(1)
	if err != nil {
		panic("Peek err: " + err.Error())
	}

	if flag[0] == 0x05 {
		log.Println("may be socks5!")
		socks5 := new(proxy.Socks5)
		socks5.Conn, socks5.ConnBufRead = conn, connBufRead
		socks5.HandleSocks5()
		return
	} else if flag[0] == 0x04 {
		log.Println("may be socks4(a)!")
		socks4 := new(proxy.Socks4)
		socks4.Conn, socks4.ConnBufRead = conn, connBufRead
		socks4.HandleSocks4()
		return
	}

	req, err := http.ReadRequest(connBufRead)
	if err != nil {
		log.Println(err)
		return
	}

	if req.Method == "CONNECT" {
		httpsProxy := new(proxy.HttpsProxy)
		httpsProxy.Conn, httpsProxy.ConnBufRead = conn, connBufRead
		httpsProxy.Req = req
		httpsProxy.HandleHttps()
	} else {
		httpProxy := new(proxy.HttpProxy)
		httpProxy.Conn, httpProxy.ConnBufRead = conn, connBufRead
		httpProxy.Req = req
		httpProxy.HandleHttp()
	}
}

func main() {
	flag.Parse()

	listenaddr := "0.0.0.0:" + strconv.Itoa(int(*port))
	ln, err := net.Listen("tcp", listenaddr)
	if err != nil {
		log.Printf("Listen error: %s\n", err)
		os.Exit(1)
	}
	log.Printf("listening on %s...\n", listenaddr)

	if *profile {
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %s\n", err)
			continue
		}
		go handleConnection(conn)
	}
}
