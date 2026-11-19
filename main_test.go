// Copyright (c) 2026 REFLEX GLOBAL B.V.
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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

func TestRelayDropsHopByHop(t *testing.T) {
	resp := &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("x")), Header: http.Header{
		"Connection": {"X-Foo"}, "X-Foo": {"1"}, "Keep-Alive": {"timeout=5"}, "Content-Type": {"application/json"},
	}}
	w := httptest.NewRecorder()
	relay(w, resp)
	if h := w.Header(); h.Get("Connection")+h.Get("X-Foo")+h.Get("Keep-Alive") != "" || h.Get("Content-Type") == "" || w.Code != 403 {
		t.Fatalf("got %d %v", w.Code, h)
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
			if r.URL.Query().Has("limit") { // real apiservers: continue token = base64 of the last name ("dev-b")
				io.WriteString(w, `{"kind":"NamespaceList","metadata":{"continue":"ZGV2LWI="},"items":[{"metadata":{"name":"dev-b"}}]}`)
				return
			}
			io.WriteString(w, `{"kind":"NamespaceList","metadata":{},"items":[{"metadata":{"name":"dev-a"}},{"metadata":{"name":"dev-b"}}]}`)
		case r.URL.Path == "/api/v1/namespaces" && (tok == "alice" || tok == "bob"):
			w.WriteHeader(http.StatusForbidden)
		case strings.HasSuffix(r.URL.Path, "selfsubjectaccessreviews") && (tok == "alice" || tok == "bob"):
			ssars.Add(1)
			b, _ := io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
			ok := tok == "alice" && r.Header.Get("Impersonate-User") == "" && strings.Contains(string(b), `"dev-a"`)
			io.WriteString(w, `{"status":{"allowed":`+map[bool]string{true: "true", false: "false"}[ok]+`}}`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer api.Close()
	apiURL, _ = url.Parse(api.URL)
	client = api.Client()
	*saDir = t.TempDir()
	os.WriteFile(*saDir+"/token", []byte("sa"), 0o600)

	var lastBody string
	list := func(tok string, hdr ...string) (int, []string) {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces", nil)
		if len(hdr) == 3 { // path, header, value
			r = httptest.NewRequest(http.MethodGet, hdr[0], nil)
			if hdr[1] != "" {
				r.Header.Set(hdr[1], hdr[2])
			}
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		listNamespaces(w, r)
		lastBody = w.Body.String()
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
	// Breaking the cache: another token, or alice impersonating someone, must not reuse alice's answers.
	if _, ns := list("bob"); len(ns) != 0 {
		t.Fatalf("bob got alice's cached SSARs: %v", ns)
	}
	if _, ns := list("alice", "/api/v1/namespaces", "Impersonate-User", "admin"); len(ns) != 0 {
		t.Fatalf("alice impersonating got alice's cached SSARs: %v", ns)
	}
	// Pagination: a continue token names the page's last namespace; filtered lists are never paged.
	if code, ns := list("alice", "/api/v1/namespaces?limit=1", "", ""); code != 200 || len(ns) != 1 || ns[0] != "dev-a" || strings.Contains(lastBody, "ZGV2LWI") {
		t.Fatalf("alice ?limit=1: %d %v %s", code, ns, lastBody)
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
	if code, _ := list("garbage"); code != 401 || !strings.Contains(lastBody, "Unauthorized: the apiserver rejected the token (not a JWT)") {
		t.Fatalf("garbage: %d %s", code, lastBody)
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
	c := &certReloader{certFile: dir + "/tls.crt", keyFile: dir + "/tls.key", metric: "test_expiry"}
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

func TestParseRequestAndWhoami(t *testing.T) {
	for _, c := range []struct{ method, path, want string }{
		{"GET", "/api/v1/namespaces/dev-a/pods", "list  dev-a pods  "},
		{"GET", "/api/v1/namespaces/dev-a/pods?watch=1", "watch  dev-a pods  "},
		{"POST", "/api/v1/namespaces/dev-a/pods/p1/exec?command=x", "create  dev-a pods exec p1"},
		{"DELETE", "/apis/apps/v1/namespaces/dev-a/deployments/web", "delete apps dev-a deployments  web"},
		{"GET", "/api/v1/namespaces/dev-a", "get  dev-a namespaces  dev-a"},
		{"PUT", "/api/v1/namespaces/dev-a/finalize", "update  dev-a namespaces finalize dev-a"},
		{"GET", "/version", "get     "},
	} {
		u, _ := url.Parse(c.path)
		ri := parseRequest(c.method, u)
		if got := strings.Join([]string{ri.verb, ri.group, ri.namespace, ri.resource, ri.subresource, ri.name}, " "); got != c.want {
			t.Errorf("%s %s: got %q want %q", c.method, c.path, got, c.want)
		}
	}

	var calls atomic.Int32
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"status":{"userInfo":{"username":"alice","groups":["devs","system:authenticated"]}}}`)
	}))
	defer api.Close()
	apiURL, _ = url.Parse(api.URL)
	client = api.Client()
	h := http.Header{"Authorization": {"Bearer alice"}}
	for range 2 {
		if u, err := whoami(h); err != nil || u.Username != "alice" || len(u.Groups) != 2 {
			t.Fatalf("whoami: %v %v", u, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("SelfSubjectReview not cached: %d calls", calls.Load())
	}
}

// With -client-cert, Orbitgate lists namespaces as that cert's CN, and user requests must
// never carry it: the apiserver would authenticate them as Orbitgate instead of the user.
func TestClientCertCredential(t *testing.T) {
	api := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		cn := ""
		if len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		switch {
		case cn != "" && tok != "":
			t.Errorf("%s %s: token %q sent together with client cert %q", r.Method, r.URL.Path, tok, cn)
			w.WriteHeader(http.StatusBadRequest)
		case r.URL.Path == "/api/v1/namespaces" && cn == "orbitgate":
			io.WriteString(w, `{"kind":"NamespaceList","metadata":{},"items":[{"metadata":{"name":"dev-a"}},{"metadata":{"name":"dev-b"}}]}`)
		case r.URL.Path == "/api/v1/namespaces" && tok == "carol":
			w.WriteHeader(http.StatusForbidden)
		case strings.HasSuffix(r.URL.Path, "selfsubjectaccessreviews") && tok == "carol":
			b, _ := io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"status":{"allowed":`+map[bool]string{true: "true", false: "false"}[strings.Contains(string(b), `"dev-a"`)]+`}}`)
		case r.URL.Path == "/readyz" && cn == "orbitgate":
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	api.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	api.StartTLS()
	defer api.Close()

	dir := t.TempDir()
	writeCert(t, dir, "orbitgate", time.Now())
	*ownCert, *ownKey = dir+"/tls.crt", dir+"/tls.key"
	*saDir = t.TempDir() // no SA token: the cert alone must do
	apiURL, _ = url.Parse(api.URL)
	client = api.Client()
	var err error
	if own, err = ownClient(client.Transport.(*http.Transport)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { own, *ownCert, *ownKey = nil, "", "" })

	r := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces", nil)
	r.Header.Set("Authorization", "Bearer carol")
	w := httptest.NewRecorder()
	listNamespaces(w, r)
	var body map[string]any
	json.Unmarshal(w.Body.Bytes(), &body)
	if ns := names(body); w.Code != 200 || len(ns) != 1 || ns[0] != "dev-a" {
		t.Fatalf("carol: %d %v %s", w.Code, ns, w.Body)
	}
	w = httptest.NewRecorder()
	metricsMux().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != 200 {
		t.Fatalf("readyz with client cert: %d %s", w.Code, w.Body)
	}

	*ownKey = dir + "/missing.key"
	if _, err := ownClient(client.Transport.(*http.Transport)); err == nil {
		t.Fatal("unreadable client key accepted")
	}
}

func jwt(claims string) string {
	return "Bearer x." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".sig"
}

func TestTokenReason(t *testing.T) {
	now := time.Unix(2000, 0)
	*trustedIss = "https://sso.cluster1.internal/realms/airlock, https://fleet.internal/realms/fleet"
	defer func() { *trustedIss = "" }()
	for _, tc := range []struct{ auth, want string }{
		{"", "no bearer token"},
		{"Bearer opaque", "not a JWT"},
		{"Bearer a.!!!.c", "unreadable JWT claims"},
		{jwt(`{"iss":"https://sso.skylab.internal/realms/airlock","exp":3000}`),
			"token issuer https://sso.skylab.internal/realms/airlock is not trusted; trusted: https://sso.cluster1.internal/realms/airlock, https://fleet.internal/realms/fleet"},
		{jwt(`{"iss":"https://fleet.internal/realms/fleet","exp":1000}`), "token from issuer https://fleet.internal/realms/fleet expired at 1970-01-01T00:16:40Z"},
		{jwt(`{"iss":"https://sso.cluster1.internal/realms/airlock","aud":"kube","exp":3000}`), "issuer https://sso.cluster1.internal/realms/airlock, audience kube (check"},
		{jwt(`{"iss":"https://evil\n\u001b[31m"}`), "token issuer https://evil[31m is not trusted"},
	} {
		if got := tokenReason(tc.auth, now); !strings.Contains(got, tc.want) {
			t.Errorf("%q: got %q, want %q", tc.auth, got, tc.want)
		}
	}
	*trustedIss = ""
	if got := tokenReason(jwt(`{"iss":"https://a"}`), now); strings.Contains(got, "not trusted") {
		t.Errorf("no -trusted-issuers must not claim untrusted: %q", got)
	}
}

// A 401 through the proxy carries the reason, as a Status kubectl can show, and never the token.
func TestExplain401(t *testing.T) {
	var buf strings.Builder
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	tok := jwt(`{"iss":"https://wrong","exp":9999999999,"sub":"s3cr3t-sub"}`)
	resp := &http.Response{StatusCode: 401, Header: http.Header{"Content-Encoding": {"gzip"}}, Body: io.NopCloser(strings.NewReader("Unauthorized")),
		Request: &http.Request{Header: http.Header{"Authorization": {tok}}}}
	*trustedIss = "https://right"
	defer func() { *trustedIss = "" }()
	explain401(resp)
	var st struct{ Kind, Message, Reason string }
	b, _ := io.ReadAll(resp.Body)
	json.Unmarshal(b, &st)
	if st.Kind != "Status" || st.Reason != "Unauthorized" || st.Message != "Unauthorized: token issuer https://wrong is not trusted; trusted: https://right" ||
		resp.ContentLength != int64(len(b)) || resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("got %s %v", b, resp.Header)
	}
	if l := buf.String(); !strings.Contains(l, "https://wrong") || strings.Contains(l, tok[7:]) || strings.Contains(l, "s3cr3t") {
		t.Fatalf("log: %q", l)
	}
}
