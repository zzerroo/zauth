package util

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"
	"unsafe"
	"zauth/zauth"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	HMAC     = "HMAC"
	Splitter = "."
)

var HMACKEY = []byte{'0', '0', 'a', '5', '7', '8', '8', '9', 'f', 'a', 'b', 'e', '0', 'e', '3', '1'}

// Byte2String ...
func Byte2String(s []byte) string {
	return *(*string)(unsafe.Pointer(&s))
}

// String2Byte ...
func String2Byte(s string) []byte {
	ps := (*[2]uintptr)(unsafe.Pointer(&s))
	d := [3]uintptr{ps[0], ps[1], ps[1]}
	return *(*[]byte)(unsafe.Pointer(&d))
}

// CalPswd ....
func CalPswd(pswd []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(pswd, bcrypt.DefaultCost)
}

// ComparePswd ...
func ComparePswd(s []byte, d []byte) error {
	return bcrypt.CompareHashAndPassword(s, d)
}

// UUID ...
func UUID() (string, error) {
	uuid, erro := uuid.NewRandom()
	if erro != nil {
		return "", erro
	}

	uuidStr := uuid.String()
	return strings.ReplaceAll(uuidStr, "-", ""), erro
}

func padding(plain []byte, blkLen int) []byte {
	padNum := blkLen - len(plain)%blkLen
	padding := bytes.Repeat([]byte{byte(padNum)}, padNum)
	return append(plain, padding...)
}

// EncryptAES ...
func EncryptAES(plain, key []byte) ([]byte, error) {
	blks, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blkPadding := padding(plain, blks.BlockSize())
	blockMode := cipher.NewCBCEncrypter(blks, key)
	blockMode.CryptBlocks(blkPadding, blkPadding)
	return plain, nil
}

// DecryptAES ...
func DecryptAES() error {
	return nil
}

func getAlgIdx(alg string) (string, error) {
	if alg == HMAC {
		return "0001", nil
	}
	return "", zauth.ErrorTkAlgNotSupported
}

// CreateTk create a new ticket, use the alg algorithm, with a static key
// the ticket is separated by .,like jwt:
// 		base64(alg) . base64(tgc . (sign time)) . sign
// 		and sign = hash(base64(alg) . base64(tgc . (sign time)))
// 	the sign is calculate use the alg algorithm, with a static key HMACKEY
func CreateTk(alg, tgc string) (string, error) {
	if len(alg) == 0 || len(tgc) == 0 {
		return "", zauth.ErrorInputParam
	}

	algIdx, erro := getAlgIdx(alg)
	if erro != nil {
		return "", erro
	}

	// add hash alg
	headerEncoding := base64.StdEncoding.EncodeToString(String2Byte(algIdx))

	// payload, payload like tgc.sign time
	signAt := time.Now()
	payLoad := tgc + Splitter + signAt.Format("20060102150405")
	payLoadEncoding := base64.StdEncoding.EncodeToString(String2Byte(payLoad))

	// the plain data include header,pay load. All is separated by .
	plainSignData := headerEncoding + Splitter + payLoadEncoding

	if alg == HMAC {
		h := hmac.New(md5.New, HMACKEY)
		io.WriteString(h, plainSignData)
		return plainSignData + Splitter + fmt.Sprintf("%x", h.Sum(nil)), nil
	}

	return "", zauth.ErrorTkAlgNotSupported
}

// VerifyTk verify the ticket
// the ticket is splitted to 3 parts,like this;
//		header . payload . sign
//		the header include the hash algorithm
//		the payload include tgc . sign time
//		the sign is the hash value of (base64(header) . base64(payload))
//	if the ticket is signed 20s ago, it is expired
func VerifyTk(ticket string) (string, error) {
	if len(ticket) == 0 {
		return "", zauth.ErrorInputParam
	}

	// check the length of ticket,should be 3: header . paylod . sign
	items := strings.Split(ticket, Splitter)
	if len(items) != 3 {
		return "", zauth.ErrorItemsLen
	}

	header := items[0]
	payLoad := items[1]
	sign := items[2]

	plainData := header + Splitter + payLoad

	//
	headerBytes, erro := base64.StdEncoding.DecodeString(header)
	if erro != nil {
		return "", erro
	}

	// check the pay load ,length should be 2,for:tgc . (sign time)
	payLoadBytes, erro := base64.StdEncoding.DecodeString(payLoad)
	if erro != nil {
		return "", erro
	}

	payLoad = Byte2String(payLoadBytes)
	payLoads := strings.Split(payLoad, Splitter)
	if len(payLoads) != 2 {
		return "", zauth.ErrorItemsLen
	}

	// check wheather the ticket is expired
	signAt := payLoads[1]
	t, erro := time.ParseInLocation("20060102150405", signAt, time.Local)
	if erro != nil {
		return "", erro
	}

	if t.After(time.Now().Add(20 * time.Second)) {
		return "", zauth.ErrorItemExpired
	}

	//
	HMACIdx, _ := getAlgIdx(HMAC)
	if HMACIdx != Byte2String(headerBytes) {
		return "", zauth.ErrorTkAlgNotSupported
	}

	h := hmac.New(md5.New, HMACKEY)
	io.WriteString(h, plainData)

	if fmt.Sprintf("%x", h.Sum(nil)) != sign {
		return "", zauth.ErrorSign
	}

	return payLoads[0], nil
}
