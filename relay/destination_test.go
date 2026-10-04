package relay

import (
	"errors"
	"testing"
)

func TestRegistryAliasesAndPorts(t *testing.T) {
	t.Parallel()
	r, err := NewRegistry([]Destination{
		{ID: "home", Aliases: []Endpoint{{Host: "Home.Example."}, {Host: "home"}}, Backend: Endpoint{Host: "127.0.0.1", Port: 2222}},
		{ID: "v6", Aliases: []Endpoint{{Host: "[2001:db8::1]", Port: 2200}}, Backend: Endpoint{Host: "::1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []Endpoint{{Host: "home.example"}, {Host: "HOME", Port: 22}} {
		target, resolveErr := r.Resolve(t.Context(), e)
		if resolveErr != nil || target.ID != "home" || target.Backend.Address() != "127.0.0.1:2222" {
			t.Fatalf("resolve %+v: %+v %v", e, target, resolveErr)
		}
	}
	v6, err := r.Resolve(t.Context(), Endpoint{Host: "2001:db8::1", Port: 2200})
	if err != nil || v6.Backend.Address() != "[::1]:22" {
		t.Fatalf("IPv6: %+v %v", v6, err)
	}
	for _, e := range []Endpoint{{Host: "home", Port: 2222}, {Host: "home", Port: 23}, {Host: "127.0.0.1"}, {Host: "evil.example"}} {
		if _, err := r.Resolve(t.Context(), e); !errors.Is(err, ErrDestination) {
			t.Fatalf("unauthorized %+v", e)
		}
	}
	if err := r.Replace([]Destination{{ID: "bad", Aliases: []Endpoint{{Host: "*"}}, Backend: Endpoint{Host: "127.0.0.1"}}}); err == nil {
		t.Fatal("accepted wildcard")
	}
	if _, err := r.Resolve(t.Context(), Endpoint{Host: "home"}); err != nil {
		t.Fatal("invalid reload replaced working snapshot")
	}
	if err := r.Replace(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(t.Context(), Endpoint{Host: "home"}); !errors.Is(err, ErrDestination) {
		t.Fatal("removed destination remains allowed")
	}
}
