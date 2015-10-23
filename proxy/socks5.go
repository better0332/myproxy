package proxy

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

const MAX_UDPBUF = 4 * 1024

var userMap = newUserMap()

type Socks5 struct {
	Proxy

	UDPConn *net.UDPConn

	User string

	connMap map[string]*replayUDPst
	lockMap sync.RWMutex
}

type replayUDPst struct {
	udpAddr *net.UDPAddr
	header  []byte
}

type userMapSt struct {
	m map[string]chan bool
	l sync.Mutex
}

func newUserMap() *userMapSt {
	u := &userMapSt{m: make(map[string]chan bool, 200)}
	return u
}

func (u *userMapSt) addUser(user string) (c chan bool) {
	u.l.Lock()
	defer u.l.Unlock()
	c = u.m[user]
	if c == nil {
		c = make(chan bool, 10)
		u.m[user] = c
	}

	return
}

func (u *userMapSt) delUser(user string) {
	u.l.Lock()
	delete(u.m, user)
	u.l.Unlock()
}

func errorReplySocks5(reason byte) []byte {
	return []byte{0x05, reason, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

func (s5 *Socks5) newConnMap() {
	s5.connMap = make(map[string]*replayUDPst, 32)
}

func (s5 *Socks5) addConnMap(client *replayUDPst, remote string) {
	s5.lockMap.Lock()
	defer s5.lockMap.Unlock()

	s5.connMap[remote] = client
}

func (s5 *Socks5) getConnMap(remote string) *replayUDPst {
	s5.lockMap.RLock()
	defer s5.lockMap.RUnlock()

	return s5.connMap[remote]
}

func (s5 *Socks5) handleSocks5_(c chan bool) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[%s]an error occurred with frontend %s: %v\n", s5.User, s5.Conn.RemoteAddr(), err)
		}
		log.Printf("[%s]disconnected from frontend %s\n", s5.User, s5.Conn.RemoteAddr())
		s5.Conn.Close()

		<-c
	}()

	// receive command
	buf3 := readBytes(s5.ConnBufRead, 4)
	protocolCheck(buf3[0] == 0x05)
	protocolCheck(buf3[2] == 0x00)

	command := buf3[1]
	if command == 0x01 { // 0x01: CONNECT
		addrtype := buf3[3]
		if addrtype == 0x01 { // 0x01: IP V4 address
			buf4 := readBytes(s5.ConnBufRead, 6)
			s5.Target = fmt.Sprintf("%d.%d.%d.%d:%d", buf4[0], buf4[1],
				buf4[2], buf4[3], int(buf4[4])<<8+int(buf4[5]))
		} else if addrtype == 0x03 { // 0x03: DOMAINNAME
			buf4 := readBytes(s5.ConnBufRead, 1)
			nmlen := int(buf4[0]) // domain name length
			buf5 := readBytes(s5.ConnBufRead, nmlen+2)
			s5.Target = fmt.Sprintf("%s:%d", buf5[0:nmlen],
				int(buf5[nmlen])<<8+int(buf5[nmlen+1]))
			s5.Domain = string(buf5[:nmlen])
		} else {
			log.Println("address type not supported")
			s5.Conn.Write(errorReplySocks5(0x08)) // address type not supported
			return
		}
		s5.handleConnect()
	} else if command == 0x03 { // 0x03: UDP ASSOCIATE
		var err error
		s5.UDPConn, err = net.ListenUDP("udp", nil)
		if err != nil {
			log.Printf("failed to ListenUDP: %v\n", err)
			s5.Conn.Write(errorReplySocks5(0x01)) // general SOCKS server failure
			return
		}
		defer s5.UDPConn.Close()

		host := s5.Conn.LocalAddr().(*net.TCPAddr).IP.String()
		port := s5.UDPConn.LocalAddr().(*net.UDPAddr).Port
		hostPort := net.JoinHostPort(host, strconv.Itoa(port))
		log.Printf("[%s]local udp addr: %s\n", s5.User, hostPort)
		localaddr := MakeSockAddr(hostPort)
		// reply command
		buf := make([]byte, 10)
		copy(buf, []byte{0x05, 0x00, 0x00, 0x01})
		copy(buf[4:], localaddr.ByteArray())
		s5.Conn.Write(buf)
		s5.Conn.(*net.TCPConn).SetKeepAlive(true)
		s5.Conn.(*net.TCPConn).SetKeepAlivePeriod(15 * time.Second)

		s5.Conn.SetDeadline(time.Time{})
		s5.newConnMap()

		go s5.handleUDP()

		io.Copy(ioutil.Discard, s5.Conn)
	} else {
		s5.Conn.Write(errorReplySocks5(0x07)) // command not supported
	}
}

func (s5 *Socks5) HandleSocks5() (ok bool) {
	buf1 := readBytes(s5.ConnBufRead, 2)
	protocolCheck(buf1[0] == 0x05)

	nom := int(buf1[1]) // number of methods
	methods := readBytes(s5.ConnBufRead, nom)

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
			log.Println("need auth!")
			s5.Conn.Write([]byte{0x05, 0x02})
			support = true
			// auth uname and passwd
			auth := readBytes(s5.ConnBufRead, 2)
			protocolCheck(auth[0] == 0x01)
			ulen := int(auth[1])
			uname = string(readBytes(s5.ConnBufRead, ulen))
			plen := readBytes(s5.ConnBufRead, 1)
			passwd = string(readBytes(s5.ConnBufRead, int(plen[0])))
			// reply auth result
			if uname != "" && uname == passwd {
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

	s5.User = uname
	c := userMap.addUser(uname)
	c <- true
	go s5.handleSocks5_(c)

	return true
}

func (s5 *Socks5) handleUDP() {
	defer s5.Conn.Close()

	for {
		buf := make([]byte, MAX_UDPBUF)
		s5.UDPConn.SetDeadline(time.Now().Add(2 * time.Minute))
		n, udpAddr, err := s5.UDPConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[%s]fail read client udp: %s\n", s5.User, udpAddr)
			return
		}
		buf = buf[:n]
		rus := s5.getConnMap(udpAddr.String())
		if rus != nil {
			// reply udp data to client
			data := make([]byte, 0, len(rus.header)+len(buf))
			data = append(data, rus.header...)
			data = append(data, buf...)
			s5.UDPConn.WriteToUDP(data, rus.udpAddr)
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
				remote = fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7], int(buf[8])<<8+int(buf[9]))
				udpData = buf[10:]
				udpHeader = append(udpHeader, buf[:10]...)
			} else if addrtype == 0x03 { // 0x03: DOMAINNAME
				nmlen := int(buf[4]) // domain name length
				nmbuf := buf[5 : 5+nmlen+2]
				remote = fmt.Sprintf("%s:%d", nmbuf[0:nmlen], int(nmbuf[nmlen])<<8+int(nmbuf[nmlen+1]))
				udpData = buf[8+nmlen:]
				udpHeader = append(udpHeader, buf[:8+nmlen]...)
			} else {
				continue // address type not supported
			}
			remoteAddr, err := net.ResolveUDPAddr("udp", remote)
			if err != nil {
				log.Printf("[%s]fail resolve name: %s\n", s5.User, remote)
				continue
			}
			//log.Printf("[%s]send udp package to remote: %s\n", remote)
			s5.addConnMap(&replayUDPst{udpAddr, udpHeader}, remoteAddr.String())
			s5.UDPConn.WriteToUDP(udpData, remoteAddr)
		}
	}
}

func (s5 *Socks5) handleConnect() {
	log.Printf("[%s]trying to connect to %s...\n", s5.User, s5.Target)
	bconn, err := net.Dial("tcp", s5.Target)
	if err != nil {
		log.Printf("[%s]failed to connect to %s: %s\n", s5.User, s5.Target, err)
		s5.Conn.Write(errorReplySocks5(0x05)) // connection refused
		return
	}
	s5.Bconn = bconn

	remoteaddr := MakeSockAddr(s5.Bconn.RemoteAddr().String())
	log.Printf("[%s]connected to backend %s\n", s5.User, remoteaddr.String())

	defer func() {
		s5.Bconn.Close()
		log.Printf("[%s]disconnected from backend %s\n", s5.User, remoteaddr.String())
	}()

	// reply command
	buf := make([]byte, 10)
	copy(buf, []byte{0x05, 0x00, 0x00, 0x01})
	copy(buf[4:], remoteaddr.ByteArray())
	s5.Conn.Write(buf)

	// reset deadline
	// s5.Conn.SetDeadline(time.Now().Add(2 * time.Hour))
	s5.Bconn.SetDeadline(time.Now().Add(2 * time.Minute))

	// proxying
	s5.proxying()
}
