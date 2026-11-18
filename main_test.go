package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestFilterListAndTable(t *testing.T) {
	allowed := map[string]bool{"dev-a": true}
	for _, raw := range []string{
		`{"kind":"NamespaceList","metadata":{"remainingItemCount":5},"items":[{"metadata":{"name":"dev-a"}},{"metadata":{"name":"dev-b"}}]}`,
		`{"kind":"Table","rows":[{"cells":["dev-a"],"object":{"metadata":{"name":"dev-a"}}},{"cells":["dev-b"],"object":{"metadata":{"name":"dev-b"}}},{"cells":["x"]}]}`,
	} {
		var body map[string]any
		json.Unmarshal([]byte(raw), &body)
		filter(body, allowed)
		if got := names(body); len(got) != 1 || got[0] != "dev-a" {
			t.Fatalf("%s: got %v", body["kind"], got)
		}
		if _, l := entries(body); len(l) != 1 {
			t.Fatalf("%s: nameless row kept", body["kind"])
		}
		if m, ok := body["metadata"].(map[string]any); ok && m["remainingItemCount"] != nil {
			t.Fatal("remainingItemCount leaked")
		}
	}
}

func TestIdentityRejectsSystem(t *testing.T) {
	*prefix = ""
	defer func() { *prefix = "oidc:" }()
	if _, err := identityFromClaims(map[string]any{"email": "a@x", "groups": []any{"system:masters"}}); err == nil {
		t.Fatal("system:masters accepted")
	}
}

func TestImpersonateStripsCallerHeaders(t *testing.T) {
	h := http.Header{"Authorization": {"Bearer x"}, "Impersonate-User": {"admin"}, "Impersonate-Extra-Foo": {"y"}}
	impersonate(h, identity{user: "oidc:a@x", groups: []string{"oidc:dev"}})
	if h.Get("Authorization") != "" || h.Get("Impersonate-Extra-Foo") != "" || h.Get("Impersonate-User") != "oidc:a@x" || h.Get("Impersonate-Group") != "oidc:dev" {
		t.Fatalf("bad headers: %v", h)
	}
}
