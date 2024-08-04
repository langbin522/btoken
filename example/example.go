package example

import (
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gctx"
	"github.com/langbin522/btoken/btoken"
)

func genToken() {
	token := &btoken.Btoken{
		CacheKey:       "bToken:",
		CacheMode:      1, //1为内存模式 重启将会失效  2为redis模式，建议使用2
		EncryptKey:     []byte("12345678912345678912345678912345"),
		MaxRefresh:     10,
		MultiLogin:     false,
		ServerName:     "test",
		Timeout:        10 * 24 * 60 * 60 * 1000,
		TokenDelimiter: "_",
	}
	data := map[string]interface{}{
		"name": "langbin522",
		"age":  18,
	}
	res := token.GenToken(gctx.New(), "test", data)
	if res.Success() {
		println("token:", res.GetString("token"))
	}
	//验证token
	tokenStr := res.GetString("token")
	res = token.ValidToken(gctx.New(), tokenStr)
	if res.Success() {
		println("token data:", res.Data)
	}
	var r *ghttp.Request //请传实际的请求对象 这里只是演示
	//或者直接解析
	res = token.GetTokenData(r) //此方法只适合 GF框架下使用
	if res.Success() {
		println("token data:", res.Data)
	}
}
