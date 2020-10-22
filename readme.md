# Zauth

zauth is a plug-in framework. currently it support cas based sso， include a mysql engine，redis or cache based session.

# Usage

## Install

go get glide get github.com/zzerroo/zauth

## Example

### sso server

more examples see [examples/example_sso_server.go](./examples/example_sso_server.go)

```go
func main() {

  auth, erro = zauth.Use(zauth.SSOAuth, zauth.MySqlEngine, zauth.CacheRedis)
  if erro != nil {
    log.Fatalf("error zauth use,info:" + erro.Error())
  }

  auth.Open("root:xxxx@tcp(127.0.0.1:3306)/auth?charset=utf8",
            "redis://:xxxx@127.0.0.1:/?active=21&idle=15&itimeout=2")
  
  http.HandleFunc("/login", loginServerSSO)
  log.Fatal(http.ListenAndServe("0.0.0.0:8081", nil))
}

func loginServerSSO(w http.ResponseWriter, r *http.Request) {

  retInfo, erro := auth.LogIn(w, r)
  if erro == zauth.ErrorNeedShowForm {
    w.Write([]byte(retInfo))
    return
  } else if erro == zauth.ErrorNeedRedirect {
		http.Redirect(w, r, retInfo, http.StatusTemporaryRedirect)
  	return
  } else if erro != nil {
    w.Write([]byte(erro.Error()))
    return
  }

  r = new(http.Request)
  http.Redirect(w, r, retInfo, http.StatusTemporaryRedirect)
  return
}
```



### client server

see [examples/example_client_server.go](./examples/example_client_server.go)