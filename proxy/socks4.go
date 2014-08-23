package proxy

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

type Socks4 struct {
	Proxy
	Type   string
	UserID string
}

func replySocks4(status byte) []byte {
	return []byte{0x00, status, 0x00, 0x0,
		0x00, 0x00, 0x00, 0x00}
}

func (s4 *Socks4) HandleSocks4() {
	buf1 := readBytes(s4.ConnBufRead, 8)
	protocolCheck(buf1[0] == 0x04)

	// command check
	protocolCheck(buf1[1] == 0x01) // only support CONNECT

	if buf1[4] == 0 && buf1[5] == 0 && buf1[6] == 0 && buf1[7] != 0 {
		s4.Type = "socks4a"
		log.Println("its socks4a")
	} else {
		s4.Type = "socks4"
		s4.Target = fmt.Sprintf("%d.%d.%d.%d:%d", buf1[4], buf1[5],
			buf1[6], buf1[7], int(buf1[2])<<8+int(buf1[3]))
		log.Println("its socks4")
	}
	userid, err := bufio.NewReader(io.LimitReader(s4.ConnBufRead, 255)).ReadString(0) // UserID max len = 255-1
	if err != nil {
		panic("userid too long!")
	}
	s4.UserID = userid
	if s4.Type == "socks4a" {
		domain, err := bufio.NewReader(io.LimitReader(s4.ConnBufRead, 256)).ReadString(0) // domain max len = 256-1
		if err != nil {
			panic("domain name too long!")
		}
		s4.Target = fmt.Sprintf("%s:%d", domain, int(buf1[2])<<8+int(buf1[3]))
		s4.Domain = domain
	}

	s4.handleConnect()
}

func (s4 *Socks4) handleConnect() {
	log.Printf("trying to connect to %s...\n", s4.Target)
	bconn, err := net.Dial("tcp", s4.Target)
	if err != nil {
		log.Printf("failed to connect to %s: %s\n", s4.Target, err)
		s4.Conn.Write(replySocks4(0x5b)) // request rejected or failed
		return
	}
	s4.Bconn = bconn

	remoteaddr := MakeSockAddr(s4.Bconn.RemoteAddr().String())
	log.Printf("connected to backend %s\n", remoteaddr.String())

	defer func() {
		s4.Bconn.Close()
		log.Printf("disconnected from backend %s\n", remoteaddr.String())
	}()

	// reply to the request
	s4.Conn.Write(replySocks4(0x5a)) // request granted

	// reset deadline
	// s4.Conn.SetDeadline(time.Now().Add(2 * time.Hour))
	s4.Bconn.SetDeadline(time.Now().Add(2 * time.Hour))

	// proxying
	s4.proxying()
}
