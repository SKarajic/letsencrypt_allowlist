package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/skarajic/letsencrypt_allowlist/traefik/config/dynamic"
	"github.com/skarajic/letsencrypt_allowlist/traefik/middlewares/ipallowlist"
)

type letsEncryptAllowLister struct {
	next          http.Handler
	name          string
	ipAllowLister http.Handler
}

func New(ctx context.Context, next http.Handler, config dynamic.IPAllowList, name string) (http.Handler, error) {
	allowLister, err := ipallowlist.New(ctx, next, config, name)
	if err != nil {
		return nil, err
	}

	return &letsEncryptAllowLister{
		next:          next,
		name:          name,
		ipAllowLister: allowLister,
	}, nil
}

func (a *letsEncryptAllowLister) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if strings.HasPrefix(req.URL.Path, "/.well-known/acme-challenge/") {
		a.next.ServeHTTP(rw, req)
		return
	}

	a.ipAllowLister.ServeHTTP(rw, req)
}
