package gowt

import (
	"net/http"
	"net/url"
)

type httpClient interface {
	Get(url string) (resp *http.Response, err error)
	PostForm(url string, data url.Values) (resp *http.Response, err error)
}

type stdHttpClient struct{}

func NewHttpClient() httpClient {
	return &stdHttpClient{}
}

func (c *stdHttpClient) Get(url string) (resp *http.Response, err error) {
	return http.Get(url)
}

func (c *stdHttpClient) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return http.PostForm(url, data)
}
