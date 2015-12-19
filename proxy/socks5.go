package proxy

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"sync/atomic"
	"time"
)

const MAX_UDPBUF = 4 * 1024

type Socks5 struct {
	Proxy
	UDPConn *net.UDPConn
	coneMap map[string]*replayUDPst
}

type replayUDPst struct {
	udpAddr *net.UDPAddr
	header  []byte
}

func errorReplySocks5(reason byte) []byte {
	return []byte{0x05, reason, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

func (s5 *Socks5) newConeMap() {
	s5.coneMap = make(map[string]*replayUDPst, 128)
}

func (s5 *Socks5) addConeMap(client *replayUDPst, remote string) {
	s5.coneMap[remote] = client
}

func (s5 *Socks5) getConeMap(remote string) *replayUDPst {
	return s5.coneMap[remote]
}

func (s5 *Socks5) handleSocks5_() {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[%s]an error occurred with frontend %s: %v\n", s5.User, s5.Conn.RemoteAddr(), err)
		}
		//log.Printf("[%s]disconnected from frontend %s\n", s5.User, s5.Conn.RemoteAddr())
		s5.Conn.Close()
		s5.freeConn()

		if s5.Info.logEnable {
			if id := s5.getTcpId(); id > 0 && len(CacheChan) < cap(CacheChan) {
				CacheChan <- &StopTcpST{id, time.Now().Format("2006-01-02 15:04:05")}
			} else {
				log.Printf("[%s][StopTcp]CacheChan is full drop tcpid %d\n", s5.User, id)
			}
		}
	}()

	// receive command
	buf3 := readBytes(s5.Conn, 4)
	protocolCheck(buf3[0] == 0x05)
	protocolCheck(buf3[2] == 0x00)

	command := buf3[1]
	if command == 0x01 { // 0x01: CONNECT
		addrtype := buf3[3]
		if addrtype == 0x01 { // 0x01: IP V4 address
			buf4 := readBytes(s5.Conn, 6)
			ip := net.IPv4(buf4[0], buf4[1], buf4[2], buf4[3])
			if !ip.IsGlobalUnicast() {
				s5.Conn.Write(errorReplySocks5(0x05)) // connection refused
				return
			}
			s5.TcpPort = uint(buf4[4])<<8 + uint(buf4[5])
			s5.Domain = ip.String()
		} else if addrtype == 0x03 { // 0x03: DOMAINNAME
			buf4 := readBytes(s5.Conn, 1)
			nmlen := int(buf4[0]) // domain name length
			buf5 := readBytes(s5.Conn, nmlen+2)
			s5.TcpPort = uint(buf5[nmlen])<<8 + uint(buf5[nmlen+1])
			s5.Domain = string(bytes.ToLower(buf5[:nmlen]))
			if isBlockDomain(s5.Domain) {
				s5.Conn.Write(errorReplySocks5(0x05)) // connection refused
				return
			}
		} else {
			log.Println("address type not supported")
			s5.Conn.Write(errorReplySocks5(0x08)) // address type not supported
			return
		}

		if isBlockPort(s5.TcpPort) {
			s5.Conn.Write(errorReplySocks5(0x05)) // connection refused
			return
		}
		s5.Target = fmt.Sprintf("%s:%d", s5.Domain, s5.TcpPort)

		if !s5.concurrencyCheck() {
			log.Printf("%s concurrencyCheck false\n", s5.User)
			s5.Conn.Write(errorReplySocks5(0x05)) // connection refused
			return
		}

		s5.handleConnect()
	} else if command == 0x03 { // 0x03: UDP ASSOCIATE
		if !s5.concurrencyCheck() {
			log.Printf("%s concurrencyCheck false\n", s5.User)
			s5.Conn.Write(errorReplySocks5(0x05)) // connection refused
			return
		}

		var err error
		s5.UDPConn, err = net.ListenUDP("udp", nil)
		if err != nil {
			log.Printf("failed to ListenUDP: %v\n", err)
			s5.Conn.Write(errorReplySocks5(0x01)) // general SOCKS server failure
			return
		}
		defer s5.UDPConn.Close()

		var host string
		ip := s5.Conn.RemoteAddr().(*net.TCPAddr).IP
		if IsIpContains(ip) {
			if s5.Info.relayServer == "" {
				log.Printf("%s can't relay sock5 proxy\n", s5.User)
				s5.Conn.Write(errorReplySocks5(0x05)) // connection refused
				return
			}
			host = ip.String()
		} else {
			host = s5.Conn.LocalAddr().(*net.TCPAddr).IP.String()
		}
		port := s5.UDPConn.LocalAddr().(*net.UDPAddr).Port
		//log.Printf("[%s]local udp addr: %s\n", s5.User, net.JoinHostPort(host, strconv.Itoa(port)))
		localaddr := SockAddr{host, port}
		// reply command
		buf := make([]byte, 10)
		copy(buf, []byte{0x05, 0x00, 0x00, 0x01})
		copy(buf[4:], localaddr.ByteArray())
		s5.Conn.Write(buf)
		s5.Conn.(*net.TCPConn).SetKeepAlive(true)
		s5.Conn.(*net.TCPConn).SetKeepAlivePeriod(15 * time.Second)

		s5.Conn.SetDeadline(time.Time{})
		s5.newConeMap()

		if s5.Info.logEnable && len(CacheChan) < cap(CacheChan) {
			CacheChan <- &InsertTcpLogST{s5.TcpId, s5.User, "UDP", s5.Conn.RemoteAddr().String(), "", time.Now().Format("2006-01-02 15:04:05")}
		}

		go s5.handleUDP()

		io.Copy(ioutil.Discard, s5.Conn)
	} else {
		s5.Conn.Write(errorReplySocks5(0x07)) // command not supported
	}
}

func (s5 *Socks5) HandleSocks5() (ok bool) {
	buf1 := readBytes(s5.Conn, 2)
	protocolCheck(buf1[0] == 0x05)

	nom := int(buf1[1]) // number of methods
	methods := readBytes(s5.Conn, nom)

	var uname, passwd string
	var support bool
OUT:
	for _, meth := range methods {
		switch meth {
		case 0x00: // not need auth
			//log.Println("not need auth!")
			//s5.Conn.Write([]byte{0x05, 0x00})
			//support = true
			//break OUT
		case 0x02: // need auth
			//log.Println("need auth!")
			s5.Conn.Write([]byte{0x05, 0x02})
			support = true
			// auth uname and passwd
			auth := readBytes(s5.Conn, 2)
			protocolCheck(auth[0] == 0x01)
			ulen := int(auth[1])
			uname = string(readBytes(s5.Conn, ulen))
			plen := readBytes(s5.Conn, 1)
			passwd = string(readBytes(s5.Conn, int(plen[0])))
			// reply auth result
			s5.Info = GetAccountInfo(uname)
			if s5.Info != nil && s5.Info.pwd == passwd {
				s5.User = uname
				s5.Conn.Write([]byte{0x01, 0x00}) // success
			} else {
				s5.Conn.Write([]byte{0x01, 0x01}) // fail
				log.Println("auth failed!")
				return
			}
			break OUT
		}
	}
	if !support {
		s5.Conn.Write([]byte{0x05, 0xff})
		log.Println("not support method!")
		return
	}

	//go s5.handleSocks5_()
	s5.handleSocks5_()
	return true
}

//Port Restricted Cone(NAT)
func (s5 *Socks5) handleUDP() {
	defer s5.Conn.Close()

	for {
		buf := make([]byte, MAX_UDPBUF)
		s5.UDPConn.SetDeadline(time.Now().Add(2 * time.Minute))
		n, udpAddr, err := s5.UDPConn.ReadFromUDP(buf)
		if err != nil {
			if !isUseOfClosedConn(err) {
				log.Printf("[%s]fail read client udp: %v\n", s5.User, err)
			}
			return
		}
		buf = buf[:n]
		rus := s5.getConeMap(udpAddr.String())
		if rus != nil {
			// reply udp data to client
			//log.Printf("[%s]%s reply udp data to client:[%q]\n", s5.User, udpAddr, buf)

			data := make([]byte, 0, len(rus.header)+len(buf))
			data = append(data, rus.header...)
			data = append(data, buf...)
			s5.UDPConn.WriteToUDP(data, rus.udpAddr)

			if s5.Info.logEnable {
				if id := s5.getTcpId(); id > 0 && len(CacheChan) < cap(CacheChan) {
					CacheChan <- &InsertUpdateUdpLogST{id, udpAddr.String(), len(buf), time.Now().Format("2006-01-02 15:04:05")}
				} else {
					log.Printf("[%s][InsertUpdateUdpLogST]CacheChan is full drop tcpid %d\n", s5.User, id)
				}
			}
			atomic.AddInt64(&s5.Info.Transfer, int64(len(buf)))
		} else {
			//send udp data to server
			if buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00 {
				continue // RSV,RSV,FRAG
			}
			udpHeader := make([]byte, 0, 10)
			addrtype := buf[3]
			var remote string
			var udpData []byte
			if addrtype == 0x01 { // 0x01: IP V4 address
				ip := net.IPv4(buf[4], buf[5], buf[6], buf[7])
				if !ip.IsGlobalUnicast() {
					continue
				}
				remote = fmt.Sprintf("%s:%d", ip.String(), uint(buf[8])<<8+uint(buf[9]))
				udpData = buf[10:]
				udpHeader = append(udpHeader, buf[:10]...)
			} else if addrtype == 0x03 { // 0x03: DOMAINNAME
				nmlen := int(buf[4]) // domain name length
				nmbuf := buf[5 : 5+nmlen+2]
				if isBlockDomain(string(nmbuf[:nmlen])) {
					continue
				}
				remote = fmt.Sprintf("%s:%d", nmbuf[:nmlen], uint(nmbuf[nmlen])<<8+uint(nmbuf[nmlen+1]))
				udpData = buf[8+nmlen:]
				udpHeader = append(udpHeader, buf[:8+nmlen]...)
			} else {
				continue // address type not supported
			}
			remoteAddr, err := net.ResolveUDPAddr("udp", remote)
			if err != nil {
				log.Printf("[%s]fail resolve dns: %v\n", s5.User, err)
				continue
			}
			//log.Printf("[%s]send udp package to %s:[%q]\n", s5.User, remote, udpData)
			s5.addConeMap(&replayUDPst{udpAddr, udpHeader}, remoteAddr.String())

			n, _ := s5.UDPConn.WriteToUDP(udpData, remoteAddr)

			if s5.Info.logEnable {
				if id := s5.getTcpId(); id > 0 && len(CacheChan) < cap(CacheChan) {
					CacheChan <- &InsertUpdateUdpLogST{id, remoteAddr.String(), n, time.Now().Format("2006-01-02 15:04:05")}
				} else {
					log.Printf("[%s][InsertUpdateUdpLogST]CacheChan is full drop tcpid %d\n", s5.User, id)
				}

			}
			atomic.AddInt64(&s5.Info.Transfer, int64(n))
		}
	}
}

func (s5 *Socks5) handleConnect() {
	//log.Printf("[%s]trying to connect to %s...\n", s5.User, s5.Target)
	bconn, err := net.Dial("tcp", s5.Target)
	if err != nil {
		log.Printf("[%s]failed to connect to %s: %s\n", s5.User, s5.Target, err)
		s5.Conn.Write(errorReplySocks5(0x05)) // connection refused
		return
	}
	s5.Bconn = bconn

	remoteaddr := MakeSockAddr(s5.Bconn.RemoteAddr().String())
	//log.Printf("[%s]connected to backend %s\n", s5.User, remoteaddr.String())

	defer func() {
		s5.Bconn.Close()
		//log.Printf("[%s]disconnected from backend %s\n", s5.User, remoteaddr.String())
	}()

	// reply command
	buf := make([]byte, 10)
	copy(buf, []byte{0x05, 0x00, 0x00, 0x01})
	copy(buf[4:], remoteaddr.ByteArray())
	s5.Conn.Write(buf)

	// reset deadline
	// s5.Conn.SetDeadline(time.Now().Add(2 * time.Hour))
	s5.Bconn.SetDeadline(time.Now().Add(2 * time.Minute))

	if s5.Info.logEnable && len(CacheChan) < cap(CacheChan) {
		CacheChan <- &InsertTcpLogST{s5.TcpId, s5.User, "TCP", s5.Conn.RemoteAddr().String(), s5.Target, time.Now().Format("2006-01-02 15:04:05")}
	}

	// proxying
	s5.proxying()
}
