package proxy

import (
	"database/sql"
	"net"
	"sync/atomic"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB
var stmtInsertTcpLog, stmtUpdateTcp, stmtStopTcp, stmtInsertUpdateUdpLog *sql.Stmt
var CacheChan = make(chan interface{}, 2000)

type InsertTcpLogST struct {
	tcpId                                                  *int64
	username, proxyType, clientAddr, remoteAddr, starttime string
}

type UpdateTcpST struct {
	id, transfer int64
}

type InsertUpdateUdpLogST struct {
	tid        int64
	remoteAddr string
	transfer   int
	addtime    string
}

type StopTcpST struct {
	id      int64
	endtime string
}

func init() {
	var err error

	db, err = sql.Open("mysql", "root@/speedmao_log?charset=utf8")
	if err != nil {
		panic(err)
	}
	db.SetMaxIdleConns(10)
	if err = db.Ping(); err != nil {
		panic(err)
	}
	if stmtInsertTcpLog, err = db.Prepare(`insert into tcp_log(username, proxy_type, client_addr, remote_addr, starttime) VALUES(?, ?, ?, ?, ?)`); err != nil {
		panic(err)
	}
	if stmtUpdateTcp, err = db.Prepare(`update tcp_log set transfer=transfer+? where id=?`); err != nil {
		panic(err)
	}
	if stmtStopTcp, err = db.Prepare(`update tcp_log set endtime=? where id=?`); err != nil {
		panic(err)
	}
	if stmtInsertUpdateUdpLog, err = db.Prepare(`insert into udp_log(tid, remote_addr, transfer, addtime) VALUES(?, ?, ?, ?) on duplicate key update transfer=transfer+?`); err != nil {
		panic(err)
	}

	for i := 0; i < 8; i++ {
		go handleSQL()
	}
}

func handleSQL() {
	for {
		inter := <-CacheChan
		switch inst := inter.(type) {
		case *InsertTcpLogST:
			atomic.StoreInt64(inst.tcpId, InsertTcpLog(inst.username, inst.proxyType, inst.clientAddr, inst.remoteAddr, inst.starttime))
		case *UpdateTcpST:
			UpdateTcp(inst.id, inst.transfer)
		case *InsertUpdateUdpLogST:
			InsertUpdateUdpLog(inst.tid, inst.remoteAddr, inst.transfer, inst.addtime)
		case *StopTcpST:
			StopTcp(inst.id, inst.endtime)
		}
	}
}

func InsertTcpLog(username, proxyType, clientAddr, remoteAddr, starttime string) int64 {
	rlt, err := stmtInsertTcpLog.Exec(username, proxyType, clientAddr, remoteAddr, starttime)
	if err != nil {
		return 0
	}
	id, _ := rlt.LastInsertId()
	return id
}

func UpdateTcp(id, transfer int64) {
	stmtUpdateTcp.Exec(transfer, id)
}

func StopTcp(id int64, endtime string) {
	stmtStopTcp.Exec(id, endtime)
}

func InsertUpdateUdpLog(tid int64, remoteAddr string, transfer int, addtime string) {
	stmtInsertUpdateUdpLog.Exec(tid, remoteAddr, transfer, addtime, transfer)
}

func SetAccountMap(m map[string]*accountInfo, h string) {
	db, err := sql.Open("mysql", "root:vps850906@(speedmao.com:3306)/speedmao?charset=utf8")
	if err != nil {
		panic(err)
	}

	var rows *sql.Rows
	if h == "" {
		rows, err = db.Query(`select username, password, log_enable, relay_server from account, order_list where order_id=order_list.id and disable=0 and money>0`)
	} else {
		rows, err = db.Query(`select username, password, log_enable, relay_server from account, order_list where order_id=order_list.id and server=? and disable=0 and money>0`, h)
	}
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	for rows.Next() {
		var logEnable int
		info := accountInfo{connMap: make(map[net.Conn]int, 10)}
		if err = rows.Scan(&info.User, &info.pwd, &info.relayServer, &logEnable); err != nil {
			panic(err)
		}
		if logEnable > 0 {
			info.logEnable = true
		}
		m[info.User] = &info
	}
}
