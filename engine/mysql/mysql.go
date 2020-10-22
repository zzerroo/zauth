package mysql

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/zzerroo/zauth"
	"github.com/zzerroo/zauth/util"

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

// Open the conn and set the init param
func (m *mysql) Open(dbDSN string) error {
	db, erro := sql.Open(MySql, dbDSN)
	if erro != nil {
		panic("error open db: " + erro.Error())
	}

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
	// create the users table, see zauth.CreateSqlStr for details
	_, erro := m.db.Exec(zauth.CreateSqlStr)
	if erro != nil {
		panic("error init table: " + erro.Error())
	}
}

// Register register a new user to the db
//	it use bcrypt to cal and store the the password to db
// Return Value:
//	nil for success,or indicate the errro
func (m *mysql) Register(info *zauth.UsrInfo) error {
	btPswd, erro := util.CalPswd(util.String2Byte(info.Pswd))
	if erro != nil {
		return zauth.ErrorCalPwd
	}

	sqlStr := fmt.Sprintf("insert into users(name,pswd,phone,email,iv) values ('%s','%s','%s','%s','%s')", info.Name, util.Byte2String(btPswd), info.Phone, info.Email, info.IV)
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

// LogIn get the user info, calc and compare the password
func (m *mysql) LogIn(name, pwd, flag string) (*zauth.UsrInfo, error) {
	u, erro := m.GetUsrInfo(name, flag)
	if erro != nil {
		return nil, erro
	}

	erro = util.ComparePswd(util.String2Byte(u.Pswd), util.String2Byte(pwd))
	if erro != nil {
		return nil, zauth.ErrorCalPwd
	}

	return u, nil
}

// GetUsrInfo get the user info accord to info 、 flag
func (m *mysql) GetUsrInfo(info, flag string) (*zauth.UsrInfo, error) {
	var s string
	if flag == zauth.FlagName {
		s = fmt.Sprintf("select name,pswd,phone,email,other from users where name=?")
	} else if flag == zauth.FlagPhone {
		s = fmt.Sprintf("select name,pswd,phone,email,other from users where phone=?")
	} else if flag == zauth.FlagEamil {
		s = fmt.Sprintf("select name,pswd,phone,email,other from users where email=?")
	}

	row := m.db.QueryRow(s, info)
	var name, pswd, phone, email, other sql.NullString
	erro := row.Scan(&name, &pswd, &phone, &email, &other)
	if erro == nil {
		return &zauth.UsrInfo{Name: name.String,
			Pswd:  pswd.String,
			Phone: phone.String,
			Email: email.String,
			Other: other.String}, nil
	}

	return nil, zauth.ErrorQuery
}
