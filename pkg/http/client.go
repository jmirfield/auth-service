package http

import (
	"io"
	"net/http"
)

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
	Post(url string, contentType string, body io.Reader) (*http.Response, error)
}
