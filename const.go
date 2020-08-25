package zauth

const (
	SSOAuth      = "sso"
	MySqlEngine  = "mysql"
	CacheSession = "cache"
	CacheRedis   = "redis"

	Name    = "name"
	Passwd  = "password"
	Flag    = "flag"
	Service = "service"
	Ticket  = "ticket"

	FlagName  = "0"
	FlagPhone = "1"
	FlagEamil = "2"

	MaxOpenConn = 100
	MaxIdelConn = 20
	MaxLifetime = 100

	TGCCookieName = "tgc"

	CreateSqlStr = `
	CREATE TABLE IF NOT EXISTS userInfo(
		id INT UNSIGNED AUTO_INCREMENT PRIMARY,
		name VARCHAR(100) NOT NULL,
		psswd VARCHAR(40) NOT NULL,
	 )ENGINE=InnoDB DEFAULT CHARSET=utf8;
	 `
)
