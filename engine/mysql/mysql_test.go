package mysql

import (
	"testing"

	"github.com/zzerroo/zauth"
)

func getMysqlConn() (*mysql, error) {
	mysql := &mysql{}
	erro := mysql.Open("root:xxx@tcp(127.0.0.1:3306)/auth?charset=utf8")
	if erro != nil {
		return nil, erro
	}

	return mysql, nil
}

func TestAll(t *testing.T) {
	mysql, erro := getMysqlConn()
	if erro != nil {
		t.Errorf("error open mysql conn")
	}

	var u1 zauth.UsrInfo
	u1.Name.String = "test1"
	u1.Pswd.String = "123456"
	u1.Email.String = "test@xxx.com"
	u1.Phone.String = "11111111111"
	u1.Other.String = ""
	erro = mysql.Register(&u1)
	if erro != nil {
		t.Errorf("error register user")
	}

	_, erro = mysql.LogIn(u1.Name.String, u1.Pswd.String, "0")
	if erro != nil {
		t.Errorf("error login 0")
	}

	_, erro = mysql.LogIn(u1.Phone.String, u1.Pswd.String, "1")
	if erro != nil {
		t.Errorf("error login 1")
	}

	_, erro = mysql.LogIn(u1.Email.String, u1.Pswd.String, "2")
	if erro != nil {
		t.Errorf("error login 2")
	}

	t.Log("ok")
}
