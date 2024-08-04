基于gtoken项目魔改版
1. 去除了中间件和部分登录验证。只保留了缓存和生成、验证TOKEN的方法
2. 将gf依懒更新到2.7.4版本

使用方法比原来的更多方便，开发者只需考虑生成和验证TOKEN即可，具体的登录流程按自己的需要进行即可以

使用方法
1. 安装依懒
2. 使用示例
    var btoken = &gtoken.GfToken{
			CacheMode:      2,
			CacheKey:       "b_token",
			Timeout:        86400000,
			TokenDelimiter: ".",
			MaxRefresh:     500000,
			EncryptKey:     []byte("0123456789100111"),
		}
    生成token 
    res:= btoken.GenToken(ctx, userkey, data)
    if res.Success() {
		fmt.Println("token",res.GetString("token"))
	}
    验证token
    res := btoken.GetTokenData(r) //这里传r是r *ghttp.Request 会自动获取token并解析出结果
	
	if res.Success() {
		return res.GetString("userKey"), res.Get("data"), nil
	}