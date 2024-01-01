package gowt

type Cacher interface {
	Get(k string) (v any, found bool)
	Set(k string, v any)
}
