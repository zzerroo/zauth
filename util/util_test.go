package util

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestUUID(t *testing.T) {
	uuidMap := make(map[string]string)
	for i := 0; i < 100; i++ {
		uuid, erro := UUID()
		if erro != nil {
			t.Error(erro.Error())
		}

		if _, ok := uuidMap[uuid]; ok {
			t.Error("error get uuid,uuid: " + uuid)
		}
	}

	t.Log("ok")
}

func TestCreateTk(t *testing.T) {
	tgc, erro := UUID()
	if erro != nil {
		t.Error(erro.Error())
	}

	ticket, erro := CreateTk("HMAC", tgc)
	if erro != nil {
		t.Error(erro.Error())
	}

	tkItems := strings.Split(ticket, ".")
	if len(tkItems) != 3 {
		t.Errorf("error length of the ticket,len:%d", len(tkItems))
	}

	header := tkItems[0]
	payLoad := tkItems[1]
	sign := tkItems[2]

	headerBytes, erro := base64.StdEncoding.DecodeString(header)
	if erro != nil {
		t.Error("error decode header,erro:" + erro.Error())
	}

	if Byte2String(headerBytes) != "HMAC" {
		t.Error("error alg,alg: " + tkItems[0])
	}

	h := hmac.New(md5.New, HMACKEY)
	io.WriteString(h, header+Splitter+payLoad)

	t.Log(fmt.Sprintf("%x", h.Sum(nil)), sign)

	if fmt.Sprintf("%x", h.Sum(nil)) != sign {
		t.Error("error sign,sign1: " + fmt.Sprintf("%x", h.Sum(nil)) + ",sign2:" + sign)
	}

	payLoadBytes, erro := base64.StdEncoding.DecodeString(payLoad)
	if erro != nil {
		t.Error("error decode payLoad,erro:" + erro.Error())
	}

	payLoadStr := Byte2String(payLoadBytes)
	payLoadItems := strings.Split(payLoadStr, Splitter)

	if len(payLoadItems) != 2 {
		t.Errorf("error len payLoadItems,len:%d", len(payLoadItems))
	}

	if payLoadItems[0] != tgc {
		t.Errorf("error payLoad tgc,item 0:%s,tgc:%s", payLoadItems[0], tgc)
	}

	t.Log("ok")
}

func TestVerifyTk(t *testing.T) {
	tgc, erro := UUID()
	if erro != nil {
		t.Error(erro.Error())
	}

	ticket, erro := CreateTk("HMAC", tgc)
	if erro != nil {
		t.Error(erro.Error())
	}

	tgcNew, erro := VerifyTk(ticket)
	if erro != nil {
		t.Error("error verify tk,error:" + erro.Error())
	}

	if tgc != tgcNew {
		t.Error("error verify tgc")
	}

	t.Log("ok")
}

func TestPasswd(t *testing.T) {
	badPswds := [...]string{"12345", "abcd", "ABCD", "123abcABC", "123abc"}
	for _, pswd := range badPswds {
		erro := CheckPsswd(pswd)
		if erro == nil {
			t.Error("bad result: " + pswd)
		}
	}

	okPswds := [...]string{"12345abcZdd!", "@Abc123", "##@@@xddd1233ZZZ", "z@ZIIIIII", "xxxxXXXX1111!!!!!"}
	for _, pswd := range okPswds {
		erro := CheckPsswd(pswd)
		if erro != nil {
			t.Error("bad result: " + pswd)
		}
	}
}

func TestEmail(t *testing.T) {
	badEmails := [...]string{"123", "123abc", "xxx#xxx.com", "123abc$xxx.cn", "!@#", "@xxx.com"}
	for _, email := range badEmails {
		erro := CheckEmail(email)
		if erro == nil {
			t.Error("bad result: " + email)
		}
	}

	okEmails := [...]string{"xxx@163.com", "abc_123@126.com", "abc.cde2@qq.com", "abc-123@baidu.com"}
	for _, email := range okEmails {
		erro := CheckEmail(email)
		if erro != nil {
			t.Error("bad result: " + email)
		}
	}
}
