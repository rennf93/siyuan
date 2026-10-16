package server

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	guardgin "github.com/rennf93/gin-guard"
	"github.com/rennf93/guard-core-go/v4/guardcore"
)

// guardEnabled 反映 SIYUAN_GUARD_ENABLED，默认关闭。
func guardEnabled(getenv func(string) string) bool {
	enabled, _ := strconv.ParseBool(getenv("SIYUAN_GUARD_ENABLED"))
	return enabled
}

// guardMiddleware 构建可选的请求防护中间件（按 IP 限流、IP 白名单/黑名单、自动封禁、查询参数攻击检测）。
// 不扫描请求体，因此笔记、资源上传和同步载荷不受影响。仅信任回环地址的代理，伪造的 X-Forwarded-For 会被忽略。
func guardMiddleware(getenv func(string) string) (gin.HandlerFunc, error) {
	rateLimit, err := guardEnvInt(getenv, "SIYUAN_GUARD_RATE_LIMIT", 600)
	if err != nil {
		return nil, err
	}
	rateWindow, err := guardEnvInt(getenv, "SIYUAN_GUARD_RATE_WINDOW", 60)
	if err != nil {
		return nil, err
	}

	noBody := false
	cfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		c.EnableRedis = false // 进程内计数，不依赖也不连接 Redis
		c.TrustedProxies = []string{"127.0.0.1", "::1"}
		c.TrustedProxyDepth = 1
		c.ExemptIPs = []string{"127.0.0.1", "::1"} // 本机桌面界面不受限
		c.Whitelist = guardEnvList(getenv("SIYUAN_GUARD_ALLOW_IPS"))
		c.Blacklist = guardEnvList(getenv("SIYUAN_GUARD_DENY_IPS"))

		c.EnableRateLimiting = true
		c.RateLimit = rateLimit
		c.RateLimitWindow = rateWindow

		c.EnableIPBanning = true
		c.AutoBanThreshold = 10
		c.AutoBanDuration = 3600

		c.EnablePenetrationDetection = true
		c.DetectionScanBody = &noBody
		c.ExcludedDetectionHeaders = map[string]bool{"cookie": true, "authorization": true}

		// 不改动响应头（界面依赖 iframe 等），静态资源与内容前缀不经过检测
		c.SecurityHeaders = nil
		c.ExcludePaths = []string{"/stage", "/appearance", "/emojis", "/assets", "/export", "/plugins", "/widgets", "/templates", "/snippets", "/public"}
	})
	if err != nil {
		return nil, fmt.Errorf("invalid SIYUAN_GUARD_* configuration: %w", err)
	}
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		return nil, err
	}
	if err = engine.Initialize(); err != nil {
		return nil, err
	}
	return guardgin.New(engine)
}

func guardEnvInt(getenv func(string) string, name string, fallback int) (int, error) {
	value := strings.TrimSpace(getenv(name))
	if "" == value {
		return fallback, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || 1 > n {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return n, nil
}

func guardEnvList(value string) (ret []string) {
	for _, item := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' }) {
		ret = append(ret, item)
	}
	return
}
