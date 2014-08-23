package cacheLayer

import (
	"errors"
	"io"
	"net"
)

const (
	Cache = iota
	NoCache
)

type CacheRead struct {
	Mode int
	Ptr  int
	buf  []byte

	io.Reader
}

func NewCacheRead(rd io.Reader) *CacheRead {
	return &CacheRead{Cache, 0, nil, rd}
}

func (cr *CacheRead) Read(p []byte) (n int, err error) {
	if cr.Mode == Cache {
		if cr.Ptr < len(cr.buf) {
			n = copy(p, cr.buf[cr.Ptr:])
			cr.Ptr += n
		} else {
			if n, err = cr.Reader.Read(p); n > 0 {
				cr.buf = append(cr.buf, p[:n]...)
				cr.Ptr += n
			}
		}
		return
	}
	if cr.Mode == NoCache {
		if cr.buf == nil {
			n, err = cr.Reader.Read(p)
		} else {
			n = copy(p, cr.buf)
			cr.buf = cr.buf[n:]
			if cr.Ptr-n > 0 {
				cr.Ptr -= n
			} else {
				cr.Ptr = 0
			}
			if len(cr.buf) == 0 {
				cr.buf = nil
			}
		}
		return
	}
	return 0, errors.New("cache no such mode")
}

type CacheConn struct {
	*CacheRead
	net.Conn
	NoCtrl bool
}

func NewCacheConn(conn net.Conn) *CacheConn {
	return &CacheConn{NewCacheRead(conn), conn, false}
}

func (cc *CacheConn) Read(p []byte) (n int, err error) {
	return cc.CacheRead.Read(p)
}

func (cc *CacheConn) Write(p []byte) (n int, err error) {
	if cc.NoCtrl {
		return cc.Conn.Write(p)
	} else {
		return 0, errors.New("cut write data")
	}
}

func (cc *CacheConn) Close() error {
	if cc.NoCtrl {
		return cc.Conn.Close()
	} else {
		return nil
	}
}

type CacheReadClose struct {
	*CacheRead
	io.ReadCloser
	NoCtrl bool
}

func NewCacheReadClose(rc io.ReadCloser) *CacheReadClose {
	return &CacheReadClose{NewCacheRead(rc), rc, false}
}

func (crc *CacheReadClose) Read(p []byte) (n int, err error) {
	return crc.CacheRead.Read(p)
}

func (crc *CacheReadClose) Close() error {
	if crc.NoCtrl {
		return crc.ReadCloser.Close()
	} else {
		return nil
	}
}
