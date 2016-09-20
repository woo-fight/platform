// Copyright (c) 2015 Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package api

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	l4g "github.com/alecthomas/log4go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/mattermost/platform/model"
	"github.com/mattermost/platform/store"
	"github.com/mattermost/platform/utils"
	"github.com/tylerb/graceful"
	"gopkg.in/throttled/throttled.v1"
	throttledStore "gopkg.in/throttled/throttled.v1/store"
	"rsc.io/letsencrypt"
)

type Server struct {
	Store           store.Store
	Router          *mux.Router
	GracefullServer *graceful.Server
}

type CorsWrapper struct {
	router *mux.Router
}

var Srv *Server

func NewServer() {

	l4g.Info(utils.T("api.server.new_server.init.info"))

	Srv = &Server{}
	Srv.Store = store.NewSqlStore()

	Srv.Router = mux.NewRouter()
	Srv.Router.NotFoundHandler = http.HandlerFunc(Handle404)
}

func StartServer() {
	l4g.Info(utils.T("api.server.start_server.starting.info"))
	l4g.Info(utils.T("api.server.start_server.listening.info"), utils.Cfg.ServiceSettings.ListenAddress)

	var handler http.Handler = &CorsWrapper{Srv.Router}

	if utils.Cfg.RateLimitSettings.EnableRateLimiter {
		l4g.Info(utils.T("api.server.start_server.rate.info"))

		vary := throttled.VaryBy{}

		if utils.Cfg.RateLimitSettings.VaryByRemoteAddr {
			vary.RemoteAddr = true
		}

		if len(utils.Cfg.RateLimitSettings.VaryByHeader) > 0 {
			vary.Headers = strings.Fields(utils.Cfg.RateLimitSettings.VaryByHeader)

			if utils.Cfg.RateLimitSettings.VaryByRemoteAddr {
				l4g.Warn(utils.T("api.server.start_server.rate.warn"))
				vary.RemoteAddr = false
			}
		}

		th := throttled.RateLimit(throttled.PerSec(utils.Cfg.RateLimitSettings.PerSec), &vary, throttledStore.NewMemStore(utils.Cfg.RateLimitSettings.MemoryStoreSize))

		th.DeniedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			l4g.Error("%v: code=429 ip=%v", r.URL.Path, GetIpAddress(r))
			throttled.DefaultDeniedHandler.ServeHTTP(w, r)
		})

		handler = th.Throttle(&CorsWrapper{Srv.Router})
	}

	Srv.GracefullServer = &graceful.Server{
		Timeout: 5 * time.Second,
		Server: &http.Server{
			Addr:         utils.Cfg.ServiceSettings.ListenAddress,
			Handler:      handlers.RecoveryHandler(handlers.PrintRecoveryStack(true))(handler),
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
		},
	}

	go func() {
		var err error
		if *utils.Cfg.ServiceSettings.ConnectionSecurity == model.CONN_SECURITY_TLS {
			if *utils.Cfg.ServiceSettings.UseLetsEncrypt {
				var m letsencrypt.Manager
				m.CacheFile(*utils.Cfg.ServiceSettings.LetsEncryptCertificateCacheFile)

				err = Srv.GracefullServer.ListenAndServeTLSConfig(&tls.Config{
					GetCertificate: m.GetCertificate,
				})
			} else {
				err = Srv.GracefullServer.ListenAndServeTLS(*utils.Cfg.ServiceSettings.TLSCertFile, *utils.Cfg.ServiceSettings.TLSKeyFile)
			}
		} else {
			err = Srv.GracefullServer.ListenAndServe()
		}
		if err != nil {
			l4g.Critical(utils.T("api.server.start_server.starting.critical"), err)
			time.Sleep(time.Second)
		}
	}()
}

func StopServer() {

	l4g.Info(utils.T("api.server.stop_server.stopping.info"))

	Srv.GracefullServer.Stop(5 * time.Second)
	Srv.Store.Close()
	hub.Stop()

	l4g.Info(utils.T("api.server.stop_server.stopped.info"))
}
