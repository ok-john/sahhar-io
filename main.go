package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/etag"
	"github.com/gofiber/fiber/v2/middleware/favicon"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/requestid"
)

const (
	PUB_URL            string = "sahhar.io"
	CERTS_PATH         string = "/etc/letsencrypt/live/" + PUB_URL
	CERT_FN            string = CERTS_PATH + "/fullchain.pem"
	KEY_FN             string = CERTS_PATH + "/privkey.pem"
	DAEMON_ENVIRONMENT string = "/var/lib/local/sahhar-io"
)

var (
	MAX_TIMEOUT             = time.Hour * 2
	l           *log.Logger = log.Default()
)

func main() {
	// defer resolution of ctx, ensures no detached servers persist the daemon
	ctx := context.Background()
	defer ctx.Done()

	// concurrently launch redirect servers
	go redirect(ctx)

	// launch main server
	log.Fatal(launch(ctx))
}

func redirect(ctx context.Context) error {
	defer ctx.Done()
	redirectServers := []*http.Server{}
	urls := []string{PUB_URL}
	ports := []string{"80", "8080"}
	for _, url := range urls {
		for _, port := range ports {
			redirectServers = append(redirectServers, __new_redirect(url+":"+port))
		}
	}

	for _, server := range redirectServers {
		go func(ctx context.Context, srv *http.Server) {
			if err := srv.ListenAndServe(); err != nil {
				ctx.Done()
				panic(err)
			}
		}(ctx, server)
	}

	return nil
}

func LaunchTLS(app *fiber.App) error {
	// Create tls certificate
	cer, err := tls.LoadX509KeyPair(CERT_FN, KEY_FN)
	if err != nil {
		return err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cer}}
	// Create custom listener
	ln, err := tls.Listen("tcp", PUB_URL+":443", config)
	if err != nil {
		return err
	}
	if err := app.Listener(ln); err != nil {
		return err
	}
	return nil
}

func inEnv(relativePath string) string {
	return path.Join(DAEMON_ENVIRONMENT, relativePath)
}

func launch(ctx context.Context) error {

	// fiber
	app := fiber.New()

	// Static fs
	app.Static("/", inEnv("public"), fiber.Static{Browse: true})

	// Middleware
	app.Use("/",
		logRequests,
		addHeaders,
		newLimiter,
		faviconHandler(),
		etag.New(),
		requestid.New(),
	)

	// Serve TLS
	if err := LaunchTLS(app); err != nil {
		return err
	}

	return nil
}

func faviconHandler() fiber.Handler {
	return favicon.New(favicon.Config{
		File: inEnv("static/img/favicon.ico"),
	})
}

func newLimiter() fiber.Handler {
	return limiter.New(limiter.Config{
		Next:         limiterMiddleware,
		Max:          20,
		Expiration:   30 * time.Second,
		LimitReached: limiterHandler,
	})
}

func limiterHandler(c *fiber.Ctx) error {
	return c.Send([]byte("Take a breather, bud."))
}

func limiterMiddleware(c *fiber.Ctx) bool {
	splitIp := strings.Split(c.IP(), ".")
	if len(splitIp) >= 4 && splitIp[0] == "10" && splitIp[1] == "10" && splitIp[2] == "10" {
		if i, err := strconv.Atoi(splitIp[3]); err == nil && (i >= 12 && i <= 32) {
			return true
		}
	}
	return false
}

func addHeaders(c *fiber.Ctx) error {
	c.Response().Header.Add("Strict-Transport-Security", "max-age=63072000")
	c.Response().Header.Add("X-Content-Type-Options", "nosniff")
	return c.Next()
}

func logRequests(c *fiber.Ctx) error {
	requestDump := strings.Join(strings.Split(c.Request().String(), "\n"), "\n\t\t")
	fullUrl := c.Request().URI().String()
	timestamp := time.Now().Format(time.Stamp)
	requestIPs := append(c.IPs(), c.IP())
	l.Printf("| %s | URL=%s | IP=%s || Request\n\t\t%+v", timestamp, fullUrl, requestIPs, requestDump)
	return c.Next()
}

// fullAddr should be format
//      ip:port
func __new_redirect(fullAddr string) *http.Server {
	return &http.Server{
		Addr: fullAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, "https://"+PUB_URL+req.RequestURI, http.StatusMovedPermanently)
		}),
		ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second,
	}
}
