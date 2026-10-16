package server

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/olahol/melody"
)

// 防护的计数在进程内按 IP 共享，因此每个测试使用各自的对端地址（203.0.113.0/24 为文档保留网段）

func guardTestEnv(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

// guardTestEngine 按 serve.go 的顺序组装 CORS 与防护，并让每个请求使用给定的对端地址。
func guardTestEngine(t *testing.T, env map[string]string, peer string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	guard, err := guardMiddleware(guardTestEnv(env))
	if err != nil {
		t.Fatal(err)
	}
	engine := gin.New()
	if err = engine.SetTrustedProxies([]string{"127.0.0.1", "::1"}); err != nil {
		t.Fatal(err)
	}
	engine.Use(func(c *gin.Context) {
		c.Request.RemoteAddr = peer
		c.Next()
	}, corsMiddleware(), guard)
	engine.Any("/*any", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return engine
}

func guardTestDo(engine *gin.Engine, method, target string, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for name, value := range header {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

func TestGuardDisabledByDefault(t *testing.T) {
	if guardEnabled(guardTestEnv(nil)) {
		t.Fatal("guard must be off unless SIYUAN_GUARD_ENABLED is set")
	}
	if guardEnabled(guardTestEnv(map[string]string{"SIYUAN_GUARD_ENABLED": "false"})) {
		t.Fatal("SIYUAN_GUARD_ENABLED=false must keep the guard off")
	}
	if !guardEnabled(guardTestEnv(map[string]string{"SIYUAN_GUARD_ENABLED": "true"})) {
		t.Fatal("SIYUAN_GUARD_ENABLED=true must turn the guard on")
	}

	// 未启用时 serve.go 不挂载任何中间件：响应不含防护头
	plain := gin.New()
	plain.Use(corsMiddleware())
	plain.GET("/api/ping", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	rec := guardTestDo(plain, http.MethodGet, "/api/ping", nil)
	for _, name := range []string{"X-Frame-Options", "Strict-Transport-Security", "X-Content-Type-Options"} {
		if rec.Header().Get(name) != "" {
			t.Fatalf("unexpected header %s without the guard", name)
		}
	}
}

func TestGuardRateLimitBurst(t *testing.T) {
	engine := guardTestEngine(t, map[string]string{"SIYUAN_GUARD_RATE_LIMIT": "3", "SIYUAN_GUARD_RATE_WINDOW": "60"}, "203.0.113.11:40000")
	for i := 0; i < 3; i++ {
		if rec := guardTestDo(engine, http.MethodPost, "/api/system/loginAuth", nil); rec.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, rec.Code)
		}
	}
	rec := guardTestDo(engine, http.MethodPost, "/api/system/loginAuth", map[string]string{"Origin": "https://notes.example.com"})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("burst: got %d, want 429", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("the CORS middleware must stay outside the guard so a 429 still carries CORS headers")
	}
	if rec.Header().Get("X-Frame-Options") != "" {
		t.Fatal("the guard must not add security headers")
	}
}

func TestGuardLocalhostExempt(t *testing.T) {
	engine := guardTestEngine(t, map[string]string{"SIYUAN_GUARD_RATE_LIMIT": "1"}, "127.0.0.1:50000")
	for i := 0; i < 5; i++ {
		if rec := guardTestDo(engine, http.MethodGet, "/api/ping", nil); rec.Code != http.StatusOK {
			t.Fatalf("local desktop request %d: got %d, want 200", i+1, rec.Code)
		}
	}
}

func TestGuardAllowList(t *testing.T) {
	env := map[string]string{"SIYUAN_GUARD_ALLOW_IPS": "198.51.100.0/24"}
	if rec := guardTestDo(guardTestEngine(t, env, "203.0.113.12:40000"), http.MethodGet, "/api/ping", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("peer outside the allowlist: got %d, want 403", rec.Code)
	}
	if rec := guardTestDo(guardTestEngine(t, env, "198.51.100.7:40000"), http.MethodGet, "/api/ping", nil); rec.Code != http.StatusOK {
		t.Fatalf("peer inside the allowlist: got %d, want 200", rec.Code)
	}
}

func TestGuardSpoofedForwardedForIgnored(t *testing.T) {
	env := map[string]string{"SIYUAN_GUARD_ALLOW_IPS": "198.51.100.0/24"}
	spoof := map[string]string{"X-Forwarded-For": "198.51.100.7"}

	// 非回环对端：伪造的 X-Forwarded-For 不能冒充白名单地址
	if rec := guardTestDo(guardTestEngine(t, env, "203.0.113.13:40000"), http.MethodGet, "/api/ping", spoof); rec.Code != http.StatusForbidden {
		t.Fatalf("spoofed X-Forwarded-For from an untrusted peer: got %d, want 403", rec.Code)
	}
	// 回环对端（本机反向代理）：采用 X-Forwarded-For 中的真实客户端地址
	if rec := guardTestDo(guardTestEngine(t, env, "127.0.0.1:50000"), http.MethodGet, "/api/ping", spoof); rec.Code != http.StatusOK {
		t.Fatalf("X-Forwarded-For from the loopback proxy: got %d, want 200", rec.Code)
	}

	// 轮换伪造地址不能绕过限流
	engine := guardTestEngine(t, map[string]string{"SIYUAN_GUARD_RATE_LIMIT": "2"}, "203.0.113.17:40000")
	var last int
	for i := 0; i < 4; i++ {
		last = guardTestDo(engine, http.MethodGet, "/api/ping", map[string]string{"X-Forwarded-For": "198.51.100." + string(rune('1'+i))}).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("rotating X-Forwarded-For must not evade the rate limit: got %d, want 429", last)
	}
}

func TestGuardBlocksAttackInQuery(t *testing.T) {
	engine := guardTestEngine(t, nil, "203.0.113.14:40000")
	if rec := guardTestDo(engine, http.MethodGet, "/check-auth?q=%3Cscript%3Ealert(1)%3C/script%3E", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("script in query: got %d, want 400 (the engine's suspicious-activity status)", rec.Code)
	}
	if rec := guardTestDo(guardTestEngine(t, nil, "203.0.113.16:40000"), http.MethodGet, "/check-auth?next=%2F", nil); rec.Code != http.StatusOK {
		t.Fatalf("benign query: got %d, want 200", rec.Code)
	}
}

func TestGuardRejectsInvalidConfig(t *testing.T) {
	for _, env := range []map[string]string{
		{"SIYUAN_GUARD_RATE_LIMIT": "0"},
		{"SIYUAN_GUARD_RATE_WINDOW": "abc"},
		{"SIYUAN_GUARD_ALLOW_IPS": "not-an-ip"},
	} {
		if _, err := guardMiddleware(guardTestEnv(env)); err == nil {
			t.Fatalf("expected an error for %v", env)
		}
	}
}

func TestGuardKeepsWebSocketAndUploadsWorking(t *testing.T) {
	gin.SetMode(gin.TestMode)
	guard, err := guardMiddleware(guardTestEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	ws := melody.New()
	defer ws.Close()
	ws.HandleMessage(func(s *melody.Session, msg []byte) { _ = s.Write(msg) })

	var uploaded int
	engine := gin.New()
	engine.Use(func(c *gin.Context) { // 真实连接，把对端改成非回环地址以确保防护真正参与
		c.Request.RemoteAddr = "203.0.113.15:40000"
		c.Next()
	}, corsMiddleware(), guard)
	engine.GET("/ws", func(c *gin.Context) { _ = ws.HandleRequest(c.Writer, c.Request) })
	engine.POST("/api/file/putFile", func(c *gin.Context) {
		form, err := c.MultipartForm()
		if err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		file, err := form.File["file"][0].Open()
		if err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		defer file.Close()
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(file)
		uploaded = buf.Len()
		c.String(http.StatusOK, "ok")
	})
	server := httptest.NewServer(engine)
	defer server.Close()

	connection, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/ws", nil)
	if err != nil {
		t.Fatalf("websocket upgrade through the guard: %v", err)
	}
	defer connection.Close()
	if err = connection.WriteMessage(websocket.TextMessage, []byte(`{"cmd":"ping"}`)); err != nil {
		t.Fatal(err)
	}
	if _, msg, err := connection.ReadMessage(); err != nil || string(msg) != `{"cmd":"ping"}` {
		t.Fatalf("websocket echo: %q, %v", msg, err)
	}

	// 4 MiB 载荷中含攻击特征文本：请求体不被扫描，必须完整到达处理函数
	payload := bytes.Repeat([]byte("<script>alert(1)</script> ' OR 1=1 -- ../../etc/passwd\n"), 80000)
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "note.sy")
	_, _ = part.Write(payload)
	_ = writer.Close()
	resp, err := http.Post(server.URL+"/api/file/putFile", writer.FormDataContentType(), body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || uploaded != len(payload) {
		t.Fatalf("upload through the guard: status %d, received %d of %d bytes", resp.StatusCode, uploaded, len(payload))
	}
}
