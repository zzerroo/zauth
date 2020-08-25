package mysql

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"time"
	"github.com/zzerroo/zauth/zauth"
	"github.com/zzerroo/zauth/zauth/util"

	_ "github.com/go-sql-driver/mysql"
)

const (
	MySql = "mysql"
)

type mysql struct {
	db *sql.DB
}

func init() {
	zauth.RegisterEngine(zauth.MySqlEngine, &mysql{})
}

func (m *mysql) Open(dbDSN string) error {
	db, erro := sql.Open(MySql, dbDSN)
	if erro != nil {
		panic("error open db: " + erro.Error())
	}

	log.Println(zauth.MaxOpenConn, zauth.MaxIdelConn, zauth.MaxLifetime)
	db.SetMaxOpenConns(zauth.MaxOpenConn)
	db.SetMaxIdleConns(zauth.MaxIdelConn)
	db.SetConnMaxLifetime(zauth.MaxLifetime * time.Second)

	if erro = db.Ping(); nil != erro {
		panic("error ping db: " + erro.Error())
	}

	m.db = db
	m.initDB()

	return nil
}

func (m *mysql) initDB() {
	createSql, erro := ioutil.ReadFile("./zauth/engine/mysql.sql")
	if erro != nil {
		panic("error read sql file: " + erro.Error())
	}

	_, erro = m.db.Exec(util.Byte2String(createSql))
	if erro != nil {
		panic("error init table: " + erro.Error())
	}
}

func (m *mysql) Register(info *zauth.UsrInfo) error {
	btPswd, erro := util.CalPswd(util.String2Byte(info.Pswd.String))
	if erro != nil {
		return zauth.ErrorCalPwd
	}

	sqlStr := fmt.Sprintf("insert into users(name,pswd,phone,email,iv) values ('%s','%s','%s','%s','%s')", info.Name.String, util.Byte2String(btPswd), info.Phone.String, info.Email.String, info.IV.String)
	fmt.Println(sqlStr)
	ret, erro := m.db.Exec(sqlStr)
	if erro != nil {
		return zauth.ErrorMysqlInsert
	}

	uid, erro := ret.LastInsertId()
	if erro != nil || uid < 0 {
		return zauth.ErrorMysqlInsert
	}
	return nil
}

func (m *mysql) getSelSQL(info string, flag string) string {
	rawSql := "select name,pswd,phone,email,other from users where "
	cond := ""
	if flag == zauth.FlagName {
		cond = fmt.Sprintf("name='%s'", info)
	} else if flag == zauth.FlagPhone {
		cond = fmt.Sprintf("phone='%s'", info)
	} else if flag == zauth.FlagEamil {
		cond = fmt.Sprintf("eamil='%s'", info)
	}
	sql := rawSql + cond

	return sql
}

// LogIn ...
func (m *mysql) LogIn(name, pwd, flag string) (*zauth.UsrInfo, error) {
	u, erro := m.GetUsrInfo(name, flag)
	if erro != nil {
		return nil, erro
	}

	erro = util.ComparePswd(util.String2Byte(u.Pswd.String), util.String2Byte(pwd))
	if erro != nil {
		return nil, erro
	}

	return u, nil
}

// GetUsrInfo ...
func (m *mysql) GetUsrInfo(info, flag string) (*zauth.UsrInfo, error) {
	var u = new(zauth.UsrInfo)

	var sql string
	if flag == zauth.FlagName {
		sql = fmt.Sprintf("select name,pswd,phone,email,other from users where name=?")
	} else if flag == zauth.FlagPhone {
		sql = fmt.Sprintf("select name,pswd,phone,email,other from users where phone=?")
	} else if flag == zauth.FlagEamil {
		sql = fmt.Sprintf("select name,pswd,phone,email,other from users where eamil=?")
	}

	row := m.db.QueryRow(sql, info)
	erro := row.Scan(&u.Name, &u.Pswd, &u.Phone, &u.Email, &u.Other)
	if erro == nil {
		return u, nil
	}

	return nil, zauth.ErrorQuery
}
