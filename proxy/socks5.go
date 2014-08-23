package proxy

import (
	"fmt"
	"log"
	"net"
	"time"
)

type Socks5 struct {
	Proxy
}

func errorReplySocks5(reason byte) []byte {
	return []byte{0x05, reason, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

func (s5 *Socks5) HandleSocks5() {
	buf1 := readBytes(s5.ConnBufRead, 2)
	protocolCheck(buf1[0] == 0x05)

	nom := int(buf1[1]) // number of methods
	methods := readBytes(s5.ConnBufRead, nom)

	support := false
	for _, meth := range methods {
		switch meth {
		case 0x00: // not need auth
			s5.Conn.Write([]byte{0x05, 0x00})
			support = true
			break
		case 0x02: // need auth
			s5.Conn.Write([]byte{0x05, 0x02})
			support = true
			// auth uname and passwd
			auth := readBytes(s5.ConnBufRead, 2)
			protocolCheck(auth[0] == 0x01)
			ulen := int(auth[1])
			uname := readBytes(s5.ConnBufRead, ulen)
			plen := readBytes(s5.ConnBufRead, 1)
			passwd := readBytes(s5.ConnBufRead, int(plen[0]))
			// reply auth result
			if uname != nil && passwd != nil {
				s5.Conn.Write([]byte{0x01, 0x00}) // success
			} else {
				s5.Conn.Write([]byte{0x01, 0x01}) // fail
				log.Println("auth failed!")
				return
			}
			break
		}
	}

	if !support {
		s5.Conn.Write([]byte{0x05, 0xff})
		log.Println("not support method!")
		return
	}

	// receive command
	buf3 := readBytes(s5.ConnBufRead, 4)
	protocolCheck(buf3[0] == 0x05)
	protocolCheck(buf3[2] == 0x00)

	command := buf3[1]
	if command != 0x01 { // 0x01: CONNECT
		s5.Conn.Write(errorReplySocks5(0x07)) // command not supported
		return
	}

	addrtype := buf3[3]
	if addrtype == 0x01 { // 0x01: IP V4 address
		buf4 := readBytes(s5.ConnBufRead, 6)
		s5.Target = fmt.Sprintf("%d.%d.%d.%d:%d", buf4[0], buf4[1],
			buf4[2], buf4[3], int(buf4[4])<<8+int(buf4[5]))
	} else if addrtype == 0x03 { // 0x03: DOMAINNAME
		buf4 := readBytes(s5.ConnBufRead, 1)
		nmlen := int(buf4[0]) // domain name length
		if nmlen > 255 {
			panic("domain name too long!")
		}

		buf5 := readBytes(s5.ConnBufRead, nmlen+2)
		s5.Target = fmt.Sprintf("%s:%d", buf5[0:nmlen],
			int(buf5[nmlen])<<8+int(buf5[nmlen+1]))
		s5.Domain = string(buf5[0:nmlen])
	} else {
		s5.Conn.Write(errorReplySocks5(0x08)) // address type not supported
		return
	}

	s5.handleConnect()
}

func (s5 *Socks5) handleConnect() {
	log.Printf("trying to connect to %s...\n", s5.Target)
	bconn, err := net.Dial("tcp", s5.Target)
	if err != nil {
		log.Printf("failed to connect to %s: %s\n", s5.Target, err)
		s5.Conn.Write(errorReplySocks5(0x05)) // connection refused
		return
	}
	s5.Bconn = bconn

	remoteaddr := MakeSockAddr(s5.Bconn.RemoteAddr().String())
	log.Printf("connected to backend %s\n", remoteaddr.String())

	defer func() {
		s5.Bconn.Close()
		log.Printf("disconnected from backend %s\n", remoteaddr.String())
	}()

	// reply to the CONNECT command
	buf := make([]byte, 10)
	copy(buf, []byte{0x05, 0x00, 0x00, 0x01})
	copy(buf[4:], remoteaddr.ByteArray())
	s5.Conn.Write(buf)

	// reset deadline
	// s5.Conn.SetDeadline(time.Now().Add(2 * time.Hour))
	s5.Bconn.SetDeadline(time.Now().Add(2 * time.Hour))

	// proxying
	s5.proxying()
}
