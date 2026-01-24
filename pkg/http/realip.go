package http

import (
	"net"
	"net/http"
)

func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}

	return r.RemoteAddr
}
