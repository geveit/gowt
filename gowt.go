package gowt

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type Gowt interface {
	Middleware(next http.Handler) http.Handler
	fetchPublicKey(kid string) (*rsa.PublicKey, error)
}

type stdGowt struct {
	config     *gowtConfig
	jsonReader jsonReader
	httpClient httpClient
	cacher     Cacher
	converter  converter
}

type gowtConfig struct {
	certsUrl string
	aud      string
}

func NewGowt(cacher Cacher) Gowt {
	return &stdGowt{
		config: &gowtConfig{
			certsUrl: os.Getenv("GOWT_CERTS_URL"),
			aud:      os.Getenv("GOWT_JWT_AUD"),
		},
		jsonReader: NewJsonReader(),
		httpClient: NewHttpClient(),
		converter:  NewConverter(),
		cacher:     cacher,
	}
}

func (g *stdGowt) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Authorization header format invalid", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			kid, _ := token.Header["kid"].(string)
			return g.fetchPublicKey(kid)
		})
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			aud, ok := claims["aud"].(string)
			if !ok || aud != g.config.aud {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), "userID", claims["sub"])
			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
	})
}

func (g *stdGowt) fetchPublicKey(kid string) (*rsa.PublicKey, error) {
	if cachedKey, found := g.cacher.Get(kid); found {
		publicKey, ok := cachedKey.(rsa.PublicKey)
		if ok {
			return &publicKey, nil
		}
	}

	publicKey, err := g.fetchPublicKeyFromServer(kid)
	if err != nil {
		return nil, err
	}

	g.cacher.Set(kid, *publicKey)

	return publicKey, nil
}

func (g *stdGowt) fetchPublicKeyFromServer(kid string) (*rsa.PublicKey, error) {
	res, err := g.httpClient.Get(g.config.certsUrl)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	resBody, err := g.jsonReader.Read(res.Body)
	if err != nil {
		return nil, err
	}

	keys, _ := resBody["keys"].([]any)

	var keyMap map[string]any
	for _, i := range keys {
		m, _ := i.(map[string]any)
		if mKid, ok := m["kid"]; ok && mKid == kid {
			keyMap = m
			break
		}
	}
	if keyMap == nil {
		return nil, fmt.Errorf("key not found for kid %s", kid)
	}

	nStr, _ := keyMap["n"].(string)

	eStr, _ := keyMap["e"].(string)

	n, err := g.converter.base64ToBigInt(nStr)
	if err != nil {
		return nil, err
	}

	e, err := g.converter.base64ToBigInt(eStr)
	if err != nil {
		return nil, err
	}

	publicKey := &rsa.PublicKey{N: n, E: int(e.Int64())}

	return publicKey, nil
}
