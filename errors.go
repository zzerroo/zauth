package zauth

import "errors"

var (
	// Common error
	ErrorInputParam  = errors.New("error input param")
	ErrorNullPointer = errors.New("error null pointer")

	// Error about session and so on
	ErrorAddSession   = errors.New("error add session")
	ErrorItemExists   = errors.New("error item exists")
	ErrorItemNotFound = errors.New("error item not found")
	ErrorItemExpired  = errors.New("error item has expired")
	ErrorItemsLen     = errors.New("error items len")

	// Error about engine and so on
	ErrorCanntOpenEngine = errors.New("error can not open engine")
	ErrorMysqlInsert     = errors.New("error can not insert data")
	ErrorQuery           = errors.New("error query data")

	ErrorLogIn = errors.New("error login")
	ErrorTkCtr = errors.New("error create ticket")

	// Error about sec
	ErrorCalPwd            = errors.New("error cal pswd")
	ErrorSign              = errors.New("error sign")
	ErrorTkAlgNotSupported = errors.New("error alg not supported")

	//
	ErrorNeedRedirect = errors.New("error need redirect")
	ErrorNeedShowForm = errors.New("error need show form")
)
