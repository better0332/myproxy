package proxy

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB
var stmtInsertTcpLog, stmtUpdateTcp, stmtStopTcp, stmtInsertUpdateUdpLog *sql.Stmt
var CacheChan = make(chan interface{}, 100)

type UpdateTcpST struct {
	Id, Transfer int64
}

type InsertUpdateUdpLogST struct {
	Tid        int64
	RemoteAddr string
	Transfer   int
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

	for i := 0; i < 5; i++ {
		go handleSQL()
	}
}

func handleSQL() {
	for {
		inter := <-CacheChan
		switch inst := inter.(type) {
		case *UpdateTcpST:
			UpdateTcp(inst.Id, inst.Transfer)
		case *InsertUpdateUdpLogST:
			InsertUpdateUdpLog(inst.Tid, inst.RemoteAddr, inst.Transfer)
		}
	}
}

func InsertTcpLog(username, proxy_type, client_addr, remote_addr string) int64 {
	rlt, err := stmtInsertTcpLog.Exec(username, proxy_type, client_addr, remote_addr)
	if err != nil {
		return 0
	}
	id, _ := rlt.LastInsertId()
	return id
}

func UpdateTcp(id int64, transfer int64) {
	stmtUpdateTcp.Exec(transfer, id)
}

func StopTcp(id int64) {
	stmtStopTcp.Exec(id)
}

func InsertUpdateUdpLog(tid int64, remote_addr string, transfer int) {
	stmtInsertUpdateUdpLog.Exec(tid, remote_addr, transfer, transfer)
}

func SetAccountMap(m map[string]*accountInfo, h string) {
	db, err := sql.Open("mysql", "root:vps850906@(speedmao.com:3306)/speedmao?charset=utf8")
	if err != nil {
		panic(err)
	}

	var rows *sql.Rows
	if h == "" {
		rows, err = db.Query(`select username, password, log_enable, relay_enable from account, order_list where order_id=order_list.id and disable=0 and money>0`)
	} else {
		rows, err = db.Query(`select username, password, log_enable, relay_enable from account, order_list where order_id=order_list.id and server=? and disable=0 and money>0`, h)
	}
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	for rows.Next() {
		var username string
		var logEnable int
		var relayEnable int
		info := accountInfo{}
		if err = rows.Scan(&username, &info.pwd, &logEnable, &relayEnable); err != nil {
			panic(err)
		}
		if logEnable > 0 {
			info.logEnable = true
		}
		if relayEnable > 0 {
			info.relayEnable = true
		}
		m[username] = &info
	}
}
