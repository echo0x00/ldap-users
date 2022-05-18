package db

import (
	"context"
	"database/sql"
	"fmt"
	"ldap/internal/config"

	_ "github.com/go-sql-driver/mysql"
)

type dbUser struct {
	full_name string
	account   string
	sid       string
	email     string
	status    int
}

func CheckUser(full_name, account, sid, email string, status int32) {
	db, err := sql.Open("mysql", config.MysqlHost)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	defer db.Close()

	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		panic(err)
	}

	// TODO надо бы оптимизировать здесь на мультизапрос

	var is_exist bool
	err = tx.QueryRow(`SELECT IF(COUNT(*),'true','false') 
					   FROM active_directory 
					   WHERE sid = ?`,
		sid).Scan(&is_exist)
	if err != nil {
		fmt.Println("39:" + err.Error())
		tx.Rollback()
		return
	}

	if is_exist {
		_, err = tx.ExecContext(ctx,
			`UPDATE active_directory 
			 SET 
				full_name = ?, 
				account = ?, 
				email = ?, 
				status = ? 
			 WHERE sid = ?`,
			full_name, account, email, status, sid)
		if err != nil {
			fmt.Println("58:" + err.Error())
			tx.Rollback()
			return
		}
	} else {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO active_directory (full_name, account, email, sid, status)
			 VALUES (?, ?, ?, ?, ?)`,
			full_name, account, email, sid, status)
		if err != nil {
			fmt.Println("68:" + err.Error())
			tx.Rollback()
			return
		}
	}

	err = tx.Commit()
	if err != nil {
		panic(err)
	}
}
