package zauth

const (
	SSOAuth      = "sso"
	MySqlEngine  = "mysql"
	CacheSession = "cache"
	CacheRedis   = "redis"

	EMail   = "email"
	Name    = "name"
	Passwd  = "password"
	Passwd1 = "password1"
	Passwd2 = "password2"
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
					 <form style="height:100%%" action="%s" method="POST" role="form" onsubmit="return true;">
							 <div id="divBorder" class="form-group divBorder">
								 <div>
									 <h1 style="text-align: center;">Welcome</h1>
								 </div><br>
								 <div class="form-group">
									 <input type="email" class="form-control" id="email" name="name" placeholder="邮箱">
									 <input type="hidden" class="form-control" id="flag" name="flag" value="2">
								 </div>
								 <div class="form-group">
									 <input type="password" class="form-control" id="password" name="password" placeholder="密码">
								 </div>
								 <div class="form-group">
									 <button width="100%%" type="submit" class="btn btn-primary btn-block">登录</button>
								 </div>
								 <div class="form-group">
								 	<label>No Account?</label>
								 	<a class="btn btn-small class="text-right" href="%s" role="button">Sign Up</a>
							 	 </div>
							 </div>
					 </form>
			 </div>
		 </body>
	 </html>
	 `
	RegisterTemplate = `
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
			.textWarning {
				background-color:#FCF8E3;
				border:1px solid #c8cace;
				box-shadow: 0 1px #e0e3e7 inset, 0 0 4px 2px rgba(0, 0, 0, 0.1);
			}
        </style>
    </head>

    <body style="background-color: #f0f0f0">
        <script src="http://libs.baidu.com/jquery/2.0.0/jquery.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@3.3.7/dist/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
		<script>
			function chkPswdPattern (s) {
				if(s.length <= 7) {
					return false;
				}

				var patternD = /^.*\d+.*$/;          
            	var patternS = /^.*[A-Za-z]+.*$/;
            	var patternSyn = /^.*[!@#~$^&*()+|_]+.*$/; 

				var addRules = 4;
				if(!patternD.test(s)) {
					addRules --;
				}

				if(!patternS.test(s)) {
					addRules --;
				}

				if(!patternSyn.test(s)) {
					addRules --;
				}

				var ret = addRules < 3? false: true
				return ret 
			}
			function chkPswd1 () {
				var pswd1 = $("#password1")[0].value

				if(false == chkPswdPattern(pswd1)){
					$("#password1").addClass("textWarning")
				} else {
					$("#password1").removeClass("textWarning")
				}
			}

			function chkPswd2 () {
				var pswd2 = document.getElementById("password2").value
				if(false == chkPswdPattern(pswd2)){
					$("#password2").addClass("textWarning")
				}

				$("#password2").removeClass("textWarning")

				var pswd1 = document.getElementById("password1").value
				if(pswd1 != pswd2) {
					$("#password1").addClass("textWarning")
					$("#password2").addClass("textWarning")
				} else {
					$("#password1").removeClass("textWarning")
					$("#password2").removeClass("textWarning")
				}
			}

			function onSubmit() {
				var pswd1 = $("#password1")[0].value
				var pswd2 = $("#password2")[0].value

				if(pswd1 != pswd2) {
					$("#password1").addClass("textWarning")
					$("#password2").addClass("textWarning")
				} else {
					$("#registerForm").submit();
				}
			}
		</script>
		<div style="position: relative;top: 20%%;margin:0 auto;width:360px;height:400px;">
                <form style="height:100%%" action="%s" method="POST" role="form" id="registerForm">
                        <div id="divBorder" class="form-group divBorder">
                            <div>
                                <h1 style="text-align: center;">Welcome</h1>
                            </div><br>
                            <div class="form-group">
                                <input type="email" class="form-control" id="email" name="email" placeholder="email">
                            </div>
                            <div class="form-group">
                                <input type="password" class="form-control" id="password1" name="password1" placeholder="Password" onblur="chkPswd1()">
                            </div>
                            <div class="form-group">
                                <input type="password" class="form-control" id="password2" name="password2" placeholder="Confirmed Password" onblur="chkPswd2()">
                            </div>
                            <div class="form-group">
                                <button width="100%%" type="submit" onclick="onSubmit()" class="btn btn-primary btn-block">Sign Up</button>
                            </div>
                        </div>
                </form>
        </div>
    </body>
</html>
	`
)
