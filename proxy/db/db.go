package db

import (
	"database/sql"
	"log"

	_ "github.com/go-sql-driver/mysql"
	// "time"
)

var db *sql.DB

// var stmt_insert_http *sql.Stmt

func init() {
	var err error

	db, err = sql.Open("mysql", "root:mysql12345+@(127.0.0.1:3306)/myproxy?charset=utf8")
	if err != nil {
		panic(err)
	}
	db.SetMaxIdleConns(5)
	/*if stmt_insert_http, err = db.Prepare(`INSERT INTO
		info(scheme, method, host, domain, path, status, reqConLen, respConLen, post, fileinfo, req, time)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`); err != nil {
		panic(err)
	}*/
}

func Insert(scheme, method, host, domain, path string, status int, reqConLen, respConLen int64,
	post, fileinfo string, req []byte) {
	/*if _, err := stmt_insert_http.Exec(scheme, method, host, domain, path,
		status, reqConLen, respConLen, post, fileinfo, req); err != nil {
		log.Println(err)
	}*/
	if _, err := db.Exec(`INSERT INTO info(scheme, method, host, domain, path, status, reqConLen, 
		respConLen, post, fileinfo, req, time)VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
		scheme, method, host, domain, path, status, reqConLen, respConLen, post, fileinfo, req); err != nil {
		log.Println(err)
	}
}
