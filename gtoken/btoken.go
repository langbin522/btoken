package gtoken

import (
	"context"
	"fmt"
	"strings"

	"github.com/gogf/gf/v2/crypto/gaes"
	"github.com/gogf/gf/v2/crypto/gmd5"
	"github.com/gogf/gf/v2/encoding/gbase64"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/gogf/gf/v2/text/gstr"
	"github.com/gogf/gf/v2/util/gconv"
	"github.com/gogf/gf/v2/util/grand"
)

// GfToken gtoken结构体
type GfToken struct {
	// GoFrame server name
	ServerName string
	// 缓存模式 1 gcache 2 gredis 默认1
	CacheMode int8
	// 缓存key
	CacheKey string
	// 超时时间 默认10天（毫秒）
	Timeout int
	// 缓存刷新时间 默认为超时时间的一半（毫秒）
	MaxRefresh int
	// Token分隔符
	TokenDelimiter string
	// Token加密key
	EncryptKey []byte
	// 认证失败中文提示
	AuthFailMsg string
	// 是否支持多端登录，默认false
	MultiLogin bool
	// 是否是全局认证，兼容历史版本，已废弃

}

/*
// Login 登录
func (m *GfToken) Login(r *ghttp.Request) {
	userKey, data := m.LoginBeforeFunc(r)
	if userKey == "" {
		g.Log().Error(r.Context(), msgLog(MsgErrUserKeyEmpty))
		return
	}

	if m.MultiLogin {
		// 支持多端重复登录，返回相同token
		userCacheResp := m.getToken(r.Context(), userKey)
		if userCacheResp.Success() {
			respToken := m.EncryptToken(r.Context(), userKey, userCacheResp.GetString(KeyUuid))
			m.LoginAfterFunc(r, respToken)
			return
		}
	}

	// 生成token
	respToken := m.genToken(r.Context(), userKey, data)
	m.LoginAfterFunc(r, respToken)

}

// Logout 登出
func (m *GfToken) Logout(r *ghttp.Request) {
	if !m.LogoutBeforeFunc(r) {
		return
	}

	// 获取请求token
	respData := m.getRequestToken(r)
	if respData.Success() {
		// 删除token
		m.RemoveToken(r.Context(), respData.DataString())
	}

	m.LogoutAfterFunc(r, respData)
}

// AuthMiddleware 认证拦截
func (m *GfToken) authMiddleware(r *ghttp.Request) {
	urlPath := r.URL.Path
	if !m.AuthPath(r.Context(), urlPath) {
		// 如果不需要认证，继续
		r.Middleware.Next()
		return
	}

	// 不需要认证，直接下一步
	if !m.AuthBeforeFunc(r) {
		r.Middleware.Next()
		return
	}

	// 获取请求token
	tokenResp := m.getRequestToken(r)
	if tokenResp.Success() {
		// 验证token
		tokenResp = m.validToken(r.Context(), tokenResp.DataString())
	}

	m.AuthAfterFunc(r, tokenResp)
}

// GetTokenData 通过token获取对象
func (m *GfToken) GetTokenData(r *ghttp.Request) Resp {
	respData := m.getRequestToken(r)
	if respData.Success() {
		// 验证token
		respData = m.validToken(r.Context(), respData.DataString())
	}

	return respData
}

// AuthPath 判断路径是否需要进行认证拦截
// return true 需要认证
func (m *GfToken) AuthPath(ctx context.Context, urlPath string) bool {
	// 去除后斜杠
	if strings.HasSuffix(urlPath, "/") {
		urlPath = gstr.SubStr(urlPath, 0, len(urlPath)-1)
	}
	// 分组拦截，登录接口不拦截
	if m.MiddlewareType == MiddlewareTypeGroup {
		if (m.LoginPath != "" && gstr.HasSuffix(urlPath, m.LoginPath)) ||
			(m.LogoutPath != "" && gstr.HasSuffix(urlPath, m.LogoutPath)) {
			return false
		}
	}

	// 全局处理，认证路径拦截处理
	if m.MiddlewareType == MiddlewareTypeGlobal {
		var authFlag bool
		for _, authPath := range m.AuthPaths {
			tmpPath := authPath
			if strings.HasSuffix(tmpPath, "/*") {
				tmpPath = gstr.SubStr(tmpPath, 0, len(tmpPath)-2)
			}
			if gstr.HasPrefix(urlPath, tmpPath) {
				authFlag = true
				break
			}
		}

		if !authFlag {
			// 拦截路径不匹配
			return false
		}
	}

	// 排除路径处理，到这里nextFlag为true
	for _, excludePath := range m.AuthExcludePaths {
		tmpPath := excludePath
		// 前缀匹配
		if strings.HasSuffix(tmpPath, "/*") {
			tmpPath = gstr.SubStr(tmpPath, 0, len(tmpPath)-2)
			if gstr.HasPrefix(urlPath, tmpPath) {
				// 前缀匹配不拦截
				return false
			}
		} else {
			// 全路径匹配
			if strings.HasSuffix(tmpPath, "/") {
				tmpPath = gstr.SubStr(tmpPath, 0, len(tmpPath)-1)
			}
			if urlPath == tmpPath {
				// 全路径匹配不拦截
				return false
			}
		}
	}

	return true
}
*/
// GetTokenData 通过token获取对象
func (m *GfToken) GetTokenData(r *ghttp.Request) Resp {
	respData := m.GetRequestToken(r)
	if respData.Success() {
		// 验证token
		respData = m.ValidToken(r.Context(), respData.DataString())
	}

	return respData
}

// getRequestToken 返回请求Token
func (m *GfToken) GetRequestToken(r *ghttp.Request) Resp {
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			g.Log().Warning(r.Context(), msgLog(MsgErrAuthHeader, authHeader))
			return Unauthorized(fmt.Sprintf(MsgErrAuthHeader, authHeader), "")
		} else if parts[1] == "" {
			g.Log().Warning(r.Context(), msgLog(MsgErrAuthHeader, authHeader))
			return Unauthorized(fmt.Sprintf(MsgErrAuthHeader, authHeader), "")
		}

		return Succ(parts[1])
	}

	authHeader = r.Get(KeyToken).String()
	if authHeader == "" {
		return Unauthorized(MsgErrTokenEmpty, "")
	}
	return Succ(authHeader)

}

// genToken 生成Token
func (m *GfToken) GenToken(ctx context.Context, userKey string, data interface{}) Resp {
	token := m.EncryptToken(ctx, userKey, "")
	if !token.Success() {
		return token
	}

	cacheKey := m.CacheKey + userKey
	userCache := g.Map{
		KeyUserKey:     userKey,
		KeyUuid:        token.GetString(KeyUuid),
		KeyData:        data,
		KeyCreateTime:  gtime.Now().TimestampMilli(),
		KeyRefreshTime: gtime.Now().TimestampMilli() + gconv.Int64(m.MaxRefresh),
	}

	cacheResp := m.setCache(ctx, cacheKey, userCache)
	if !cacheResp.Success() {
		return cacheResp
	}

	return token
}

// validToken 验证Token
func (m *GfToken) ValidToken(ctx context.Context, token string) Resp {
	if token == "" {
		return Unauthorized(MsgErrTokenEmpty, "")
	}

	decryptToken := m.DecryptToken(ctx, token)
	if !decryptToken.Success() {
		return decryptToken
	}

	userKey := decryptToken.GetString(KeyUserKey)
	uuid := decryptToken.GetString(KeyUuid)

	userCacheResp := m.GetToken(ctx, userKey)
	if !userCacheResp.Success() {
		return userCacheResp
	}

	if uuid != userCacheResp.GetString(KeyUuid) {
		g.Log().Debug(ctx, msgLog(MsgErrAuthUuid)+", decryptToken:"+decryptToken.Json()+" cacheValue:"+gconv.String(userCacheResp.Data))
		return Unauthorized(MsgErrAuthUuid, "")
	}

	return userCacheResp
}

// getToken 通过userKey获取Token
func (m *GfToken) GetToken(ctx context.Context, userKey string) Resp {
	cacheKey := m.CacheKey + userKey

	userCacheResp := m.getCache(ctx, cacheKey)
	if !userCacheResp.Success() {
		return userCacheResp
	}
	userCache := gconv.Map(userCacheResp.Data)

	nowTime := gtime.Now().TimestampMilli()
	refreshTime := userCache[KeyRefreshTime]

	// 需要进行缓存超时时间刷新
	if gconv.Int64(refreshTime) == 0 || nowTime > gconv.Int64(refreshTime) {
		userCache[KeyCreateTime] = gtime.Now().TimestampMilli()
		userCache[KeyRefreshTime] = gtime.Now().TimestampMilli() + gconv.Int64(m.MaxRefresh)
		return m.setCache(ctx, cacheKey, userCache)
	}

	return Succ(userCache)
}

// RemoveToken 删除Token
func (m *GfToken) RemoveToken(ctx context.Context, token string) Resp {
	decryptToken := m.DecryptToken(ctx, token)
	if !decryptToken.Success() {
		return decryptToken
	}

	cacheKey := m.CacheKey + decryptToken.GetString(KeyUserKey)
	return m.removeCache(ctx, cacheKey)
}

// EncryptToken token加密方法
func (m *GfToken) EncryptToken(ctx context.Context, userKey string, uuid string) Resp {
	if userKey == "" {
		return Fail(MsgErrUserKeyEmpty)
	}

	if uuid == "" {
		// 重新生成uuid
		newUuid, err := gmd5.Encrypt(grand.Letters(10))
		if err != nil {
			g.Log().Error(ctx, msgLog(MsgErrAuthUuid), err)
			return Error(MsgErrAuthUuid)
		}
		uuid = newUuid
	}

	tokenStr := userKey + m.TokenDelimiter + uuid

	token, err := gaes.Encrypt([]byte(tokenStr), m.EncryptKey)
	if err != nil {
		g.Log().Error(ctx, msgLog(MsgErrTokenEncrypt), tokenStr, err)
		return Error(MsgErrTokenEncrypt)
	}

	return Succ(g.Map{
		KeyUserKey: userKey,
		KeyUuid:    uuid,
		KeyToken:   gbase64.EncodeToString(token),
	})
}

// DecryptToken token解密方法
func (m *GfToken) DecryptToken(ctx context.Context, token string) Resp {
	if token == "" {
		return Fail(MsgErrTokenEmpty)
	}

	token64, err := gbase64.Decode([]byte(token))
	if err != nil {
		g.Log().Error(ctx, msgLog(MsgErrTokenDecode), token, err)
		return Error(MsgErrTokenDecode)
	}
	decryptToken, err2 := gaes.Decrypt(token64, m.EncryptKey)
	if err2 != nil {
		g.Log().Error(ctx, msgLog(MsgErrTokenEncrypt), token, err2)
		return Error(MsgErrTokenEncrypt)
	}
	tokenArray := gstr.Split(string(decryptToken), m.TokenDelimiter)
	if len(tokenArray) < 2 {
		g.Log().Error(ctx, msgLog(MsgErrTokenLen), token)
		return Error(MsgErrTokenLen)
	}

	return Succ(g.Map{
		KeyUserKey: tokenArray[0],
		KeyUuid:    tokenArray[1],
	})
}

// String token解密方法
func (m *GfToken) String() string {
	return gconv.String(g.Map{
		// 缓存模式 1 gcache 2 gredis 默认1
		"CacheMode":      m.CacheMode,
		"CacheKey":       m.CacheKey,
		"Timeout":        m.Timeout,
		"TokenDelimiter": m.TokenDelimiter,
		"AuthFailMsg":    m.AuthFailMsg,
		"MultiLogin":     m.MultiLogin,
	})
}
