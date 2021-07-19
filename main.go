package main

import (
	"context"
	"crypto/tls"
	"flag"
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
	CERTS_PATH                = "/etc/letsencrypt/live/sahhar.io"
	CERT_FN                   = CERTS_PATH + "/fullchain.pem"
	KEY_FN                    = CERTS_PATH + "/privkey.pem"
	PUB_URL            string = "sahhar.io"
	DAEMON_ENVIRONMENT string = "/var/lib/local/sahhar-io"
)

var (
	MAX_TIMEOUT = time.Hour * 2
	user_env    = DAEMON_ENVIRONMENT
)

func main() {
	// Start
	ctx := context.Background()
	defer ctx.Done()
	environment := flag.String("e", DAEMON_ENVIRONMENT, "env path for daemon")
	flag.Parse()
	user_env = *environment
	go redirect(ctx)
	log.Fatal(launch())
}

func inEnv(relativePath string) string {
	return path.Join(user_env, relativePath)
}

func launch() error {
	l := log.Default()
	app := fiber.New()
	app.Static("/", inEnv("public"), fiber.Static{Browse: true})
	app.Use("/",
		func(c *fiber.Ctx) error {
			requestDump := strings.Join(strings.Split(c.Request().String(), "\n"), "\n\t\t")
			fullUrl := c.Request().URI().String()
			timestamp := time.Now().Format(time.Stamp)
			requestIPs := append(c.IPs(), c.IP())
			l.Printf("| %s | URL=%s | IP=%s || Request\n\t\t%+v", timestamp, fullUrl, requestIPs, requestDump)
			return c.Next()
		},
		etag.New(),
		requestid.New(),
		favicon.New(favicon.Config{
			File: inEnv("static/img/favicon.ico"),
		}),
		func(c *fiber.Ctx) error {
			c.Response().Header.Add("Strict-Transport-Security", "max-age=63072000")
			c.Response().Header.Add("X-Content-Type-Options", "nosniff")
			return c.Next()
		},
		limiter.New(limiter.Config{
			Next: func(c *fiber.Ctx) bool {
				if c.IP() == "127.0.0.1" {
					return true
				}
				splitIp := strings.Split(c.IP(), ".")
				if len(splitIp) >= 4 && splitIp[0] == "10" && splitIp[1] == "10" && splitIp[2] == "10" {
					if i, err := strconv.Atoi(splitIp[3]); err == nil && (i >= 12 && i <= 32) {
						return true
					}
				}
				return false
			},
			Max:        20,
			Expiration: 30 * time.Second,
			LimitReached: func(c *fiber.Ctx) error {
				return c.Send([]byte("Take a breather, bud."))
			},
		}))

	//Run
	if err := LaunchTLS(app); err != nil {
		return err
	}

	return nil
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
