package idp

import (
	"errors"
	"strings"
)

type Registry struct {
	providers map[string]Provider
}

func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
	}
}

func (r *Registry) Register(p Provider) error {
	if p == nil {
		return errors.New("missing provider")
	}
	name := strings.ToLower(strings.TrimSpace(p.Name()))
	if name == "" {
		return errors.New("missing provider name")
	}
	if _, exists := r.providers[name]; exists {
		return errors.New("provider already registered")
	}
	r.providers[name] = p
	return nil
}

func (r *Registry) Get(name string) (Provider, bool) {
	if r == nil {
		return nil, false
	}
	key := strings.ToLower(strings.TrimSpace(name))
	p, ok := r.providers[key]
	return p, ok
}
