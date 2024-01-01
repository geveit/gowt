package gowt

import (
	"net/http"
)

type httpClient interface {
	Get(url string) (resp *http.Response, err error)
}

type stdHttpClient struct{}

func NewHttpClient() httpClient {
	return &stdHttpClient{}
}

func (c *stdHttpClient) Get(url string) (resp *http.Response, err error) {
	return http.Get(url)
}
