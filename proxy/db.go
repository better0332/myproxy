package proxy

import (
	"database/sql"
	"net"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB
var stmtInsertTcpLog, stmtUpdateTcp, stmtStopTcp, stmtInsertUpdateUdpLog *sql.Stmt

func init() {
	var err error

	db, err = sql.Open("mysql", "root@/speedmao_log?charset=utf8")
	if err != nil {
		panic(err)
	}
	db.SetMaxIdleConns(10)
	//	if err = db.Ping(); err != nil {
	//		panic(err)
	//	}
	if stmtInsertTcpLog, err = db.Prepare(`insert into tcp_log(username, proxy_type, client_addr, remote_addr, starttime) VALUES(?, ?, ?, ?, now())`); err != nil {
		panic(err)
	}
	if stmtUpdateTcp, err = db.Prepare(`update tcp_log set transfer=transfer+? where id=?`); err != nil {
		panic(err)
	}
	if stmtStopTcp, err = db.Prepare(`update tcp_log set endtime=now() where id=?`); err != nil {
		panic(err)
	}
	if stmtInsertUpdateUdpLog, err = db.Prepare(`insert into udp_log(tid, remote_addr, transfer, addtime) VALUES(?, ?, ?, now()) on duplicate key update transfer=transfer+?`); err != nil {
		panic(err)
	}
}

func InsertTcpLog(username, proxyType, clientAddr, remoteAddr string) int64 {
	rlt, err := stmtInsertTcpLog.Exec(username, proxyType, clientAddr, remoteAddr)
	if err != nil {
		return 0
	}
	id, _ := rlt.LastInsertId()
	return id
}

func UpdateTcp(id, transfer int64) {
	stmtUpdateTcp.Exec(transfer, id)
}

func StopTcp(id int64) {
	stmtStopTcp.Exec(id)
}

func InsertUpdateUdpLog(tid int64, remoteAddr string, transfer int64) {
	stmtInsertUpdateUdpLog.Exec(tid, remoteAddr, transfer, transfer)
}

func SetAccountMap(m map[string]*accountInfo, h string) {
	db, err := sql.Open("mysql", "root:vps850906@(speedmao.com:3306)/speedmao?charset=utf8")
	if err != nil {
		panic(err)
	}

	rows, err := db.Query(`select username, password, relay_server, log_enable from account, order_list where order_id=order_list.id and server=? and disable=0 and money>0`, h)
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
		if info.relayServer != "" {
			info.relayServer, _, err = net.SplitHostPort(info.relayServer)
			if err != nil {
				panic(err)
			}
			if err = SetRelayMap(info.relayServer); err != nil {
				panic(err)
			}
		}
		if logEnable > 0 {
			info.logEnable = true
		}
		m[info.User] = &info
	}
}
