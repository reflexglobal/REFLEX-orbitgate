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
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
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
	var ssars atomic.Int32
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch {
		case r.URL.Path == "/api/v1/namespaces" && tok == "sa" && r.URL.Query().Get("watch") == "true":
			for _, ev := range []string{
				`{"type":"ADDED","object":{"kind":"Namespace","metadata":{"name":"dev-a"}}}`,
				`{"type":"ADDED","object":{"kind":"Namespace","metadata":{"name":"dev-b"}}}`,
				`{"type":"BOOKMARK","object":{"kind":"Namespace","metadata":{"resourceVersion":"7"}}}`,
				`{"type":"MODIFIED","object":{"kind":"Table","rows":[{"object":{"metadata":{"name":"dev-b"}}},{"object":{"metadata":{"name":"dev-a"}}}]}}`,
				`{"type":"MODIFIED","object":{"kind":"Table","rows":[{"object":{"metadata":{"name":"dev-b"}}}]}}`,
			} {
				io.WriteString(w, ev+"\n")
			}
		case r.URL.Path == "/api/v1/namespaces" && (tok == "sa" || tok == "admin"):
			io.WriteString(w, `{"kind":"NamespaceList","metadata":{},"items":[{"metadata":{"name":"dev-a"}},{"metadata":{"name":"dev-b"}}]}`)
		case r.URL.Path == "/api/v1/namespaces" && tok == "alice":
			w.WriteHeader(http.StatusForbidden)
		case strings.HasSuffix(r.URL.Path, "selfsubjectaccessreviews") && tok == "alice":
			ssars.Add(1)
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
	if n := ssars.Load(); n != 2 {
		t.Fatalf("alice: %d SSARs, want 2", n)
	}
	if code, ns := list("alice"); code != 200 || len(ns) != 1 || ssars.Load() != 2 {
		t.Fatalf("alice again: %d %v, SSARs %d (want cached)", code, ns, ssars.Load())
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces?watch=true", nil)
	r.Header.Set("Authorization", "Bearer alice")
	w := httptest.NewRecorder()
	listNamespaces(w, r)
	var got []string
	for _, line := range strings.Split(strings.TrimSpace(w.Body.String()), "\n") {
		var ev map[string]any
		json.Unmarshal([]byte(line), &ev)
		obj := ev["object"].(map[string]any)
		got = append(got, fmt.Sprintf("%v %s%v", ev["type"], nameOf(obj), names(obj)))
	}
	if g := strings.Join(got, ", "); g != "ADDED dev-a[], BOOKMARK [], MODIFIED [dev-a]" {
		t.Fatalf("alice watch: %s", g)
	}
	if !isWatch(url.Values{"watch": {""}}) || isWatch(url.Values{"watch": {"FALSE"}}) || isWatch(nil) {
		t.Fatal("isWatch must parse like the apiserver")
	}
	if code, _ := list("garbage"); code != 401 {
		t.Fatalf("garbage: %d", code)
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

func TestAccessLogNoCredentials(t *testing.T) {
	var buf strings.Builder
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	*accessLog = true
	h := observe(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/x/pods/p/exec?command=secret", nil)
	r.Header.Set("Authorization", "Bearer s3cr3t")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if l := buf.String(); !strings.Contains(l, "GET /api/v1/namespaces/x/pods/p/exec 403") || strings.Contains(l, "secret") || strings.Contains(l, "s3cr3t") {
		t.Fatalf("access log: %q", l)
	}
}

func TestMetricsAndReadyz(t *testing.T) {
	ready := true
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ready {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer api.Close()
	apiURL, _ = url.Parse(api.URL)
	client = api.Client()
	*saDir = t.TempDir()
	get := func(path string) (int, string) {
		w := httptest.NewRecorder()
		metricsMux().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w.Code, w.Body.String()
	}
	if code, _ := get("/readyz"); code != 200 {
		t.Fatalf("readyz: %d", code)
	}
	ready = false
	if code, _ := get("/readyz"); code != 503 {
		t.Fatalf("readyz with apiserver down: %d", code)
	}
	inc("orbitgate_ssar_errors_total")
	observe(http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	if _, m := get("/metrics"); !strings.Contains(m, "# TYPE orbitgate_ssar_errors_total counter\norbitgate_ssar_errors_total ") ||
		!strings.Contains(m, `orbitgate_requests_total{code="404"} `) {
		t.Fatalf("metrics:\n%s", m)
	}
}
