// Copyright (c) 2026 REFLEX GLOBAL B.V.
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
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

// Fake apiserver: "sa" and "admin" may list namespaces, "alice" is forbidden but may list pods in dev-a.
func TestListNamespacesPassthroughAndFallback(t *testing.T) {
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch {
		case r.URL.Path == "/api/v1/namespaces" && (tok == "sa" || tok == "admin"):
			io.WriteString(w, `{"kind":"NamespaceList","metadata":{},"items":[{"metadata":{"name":"dev-a"}},{"metadata":{"name":"dev-b"}}]}`)
		case r.URL.Path == "/api/v1/namespaces" && tok == "alice":
			w.WriteHeader(http.StatusForbidden)
		case strings.HasSuffix(r.URL.Path, "selfsubjectaccessreviews") && tok == "alice":
			b, _ := io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"status":{"allowed":`+map[bool]string{true: "true", false: "false"}[strings.Contains(string(b), `"dev-a"`)]+`}}`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer api.Close()
	apiURL, _ = url.Parse(api.URL)
	client = api.Client()
	*saDir = t.TempDir()
	os.WriteFile(*saDir+"/token", []byte("sa"), 0o600)

	list := func(tok string) (int, []string) {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		listNamespaces(w, r)
		var body map[string]any
		json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, names(body)
	}
	if code, ns := list("admin"); code != 200 || len(ns) != 2 {
		t.Fatalf("admin: %d %v", code, ns)
	}
	if code, ns := list("alice"); code != 200 || len(ns) != 1 || ns[0] != "dev-a" {
		t.Fatalf("alice: %d %v", code, ns)
	}
	if code, _ := list("garbage"); code != 401 {
		t.Fatalf("garbage: %d", code)
	}
}

func TestCAReload(t *testing.T) {
	api := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer api.Close()
	*saDir = t.TempDir()
	ca := *saDir + "/ca.crt"
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "wrong CA"}, NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	apiCA = &caReloader{}
	c := &http.Client{Transport: newTransport()}
	if _, err := c.Get(api.URL); err == nil {
		t.Fatal("untrusted apiserver accepted")
	}
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw}), 0o600)
	later := time.Now().Add(time.Second)
	os.Chtimes(ca, later, later)
	if _, err := c.Get(api.URL); err != nil {
		t.Fatalf("rotated CA not picked up: %v", err)
	}
}

func writeCert(t *testing.T, dir, cn string, mod time.Time) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(dir+"/tls.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	os.WriteFile(dir+"/tls.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.Chtimes(dir+"/tls.crt", mod, mod)
}

func TestCertReload(t *testing.T) {
	dir := t.TempDir()
	*tlsCert, *tlsKey = dir+"/tls.crt", dir+"/tls.key"
	c := &certReloader{}
	cn := func() string {
		cert, err := c.get(nil)
		if err != nil {
			t.Fatal(err)
		}
		return cert.Leaf.Subject.CommonName
	}
	now := time.Now()
	writeCert(t, dir, "old", now)
	if cn() != "old" {
		t.Fatal("initial load")
	}
	writeCert(t, dir, "new", now.Add(time.Second))
	if cn() != "new" {
		t.Fatal("rotation not picked up")
	}
	os.WriteFile(dir+"/tls.key", []byte("garbage"), 0o600)
	os.Chtimes(dir+"/tls.crt", now.Add(2*time.Second), now.Add(2*time.Second))
	if cn() != "new" {
		t.Fatal("broken rotation should keep last good cert")
	}
}
