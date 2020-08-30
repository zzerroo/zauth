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
	Step    = "step"

	FlagName  = "0"
	FlagPhone = "1"
	FlagEamil = "2"

	MaxOpenConn = 100
	MaxIdelConn = 20
	MaxLifetime = 100

	TGCCookieName = "tgc"

	CreateSqlStr = `
	CREATE TABLE IF NOT EXISTS users (
		uid int(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
		name varchar(100) UNIQUE NOT NULL,
		pswd varchar(100) NOT NULL,
		iv char(64) NOT NULL,
		phone char(11) UNIQUE,
		email char(128) UNIQUE,
		status SMALLINT DEFAULT 1 NOT NULL,
		other varchar(512) DEFAULT NULL,
		regdate timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
	  ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
	 `
	LoginTemplate = `
	 <html>
		 <head>
			 <meta charset="utf-8">
			 <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
			 <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@3.3.7/dist/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
		 
			 <style>
				 .divBorder {
					 background-color:white;
					 opacity: 0.9;
					 border:1px solid #c8cace;
					 box-shadow: 0 1px #e0e3e7 inset, 0 0 10px 5px rgba(0, 0, 0, 0.1);
					 border-radius:8px;
					 padding-top: 70px;
					 padding-left: 30px;
					 padding-right: 30px;
					 height: 100%%;
				 }
			 </style>
		 </head>
	 
		 <body style="background-color: #f0f0f0">
			 <script src="https://cdn.jsdelivr.net/npm/bootstrap@3.3.7/dist/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
			 <div style="position: relative;top: 20%%;margin:0 auto;width:360px;height:400px;">
					 <form style="height:100%%" action="%s" method="POST">
							 <div id="divBorder" class="form-group divBorder">
								 <div>
									 <h1 style="text-align: center;">Name</h1>
								 </div><br>
								 <div class="form-group">
									 <input type="email" class="form-control" id="email" placeholder="Name">
								 </div>
								 <div class="form-group">
									 <input type="password" class="form-control" id="inputPassword3" placeholder="Password">
								 </div>
								 <div class="form-group">
									 <label><input type="checkbox"> Remember me</label>
								 </div>
								 <div class="form-group">
									 <button width="100%" type="submit" class="btn btn-primary btn-block">Sign in</button>
								 </div>
							 </div>
					 </form>
			 </div>
		 </body>
	 </html>
	 `
)
