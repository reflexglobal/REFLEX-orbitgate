// Copyright (c) 2026 REFLEX GLOBAL B.V.
// SPDX-License-Identifier: MIT

// Orbitgate: a pass-through kube-apiserver proxy that only lists the namespaces
// a user has access to. Authentication, RBAC, admission and audit stay with the
// apiserver: user credentials are forwarded untouched.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	listen    = flag.String("listen", ":8443", "listen address")
	tlsCert   = flag.String("tls-cert", "", "TLS cert file (reloaded on change)")
	tlsKey    = flag.String("tls-key", "", "TLS key file")
	plainHTTP = flag.Bool("plain-http", false, "serve plain HTTP (only behind a TLS-terminating LB/ingress)")
	apiserver = flag.String("apiserver", "https://kubernetes.default.svc", "kube-apiserver URL")
	saDir     = flag.String("sa-dir", "/var/run/secrets/kubernetes.io/serviceaccount", "dir with token + ca.crt")
	printVer  = flag.Bool("version", false, "print the version and exit")
	accessLog = flag.Bool("access-log", false, "log every request: client IP, method, path, status, duration (never credentials)")
)

var version = "dev" // set at build time: -ldflags "-X main.version=X.Y.Z"

var (
	apiURL *url.URL
	client *http.Client
)

func main() {
	flag.Parse()
	if *printVer {
		fmt.Println(version)
		return
	}
	log.Printf("orbitgate %s", version)
	if !*plainHTTP && (*tlsCert == "" || *tlsKey == "") {
		log.Fatal("-tls-cert/-tls-key required (or -plain-http behind a TLS-terminating LB)")
	}

	var err error
	if apiURL, err = url.Parse(*apiserver); err != nil {
		log.Fatal(err)
	}
	ca, err := os.ReadFile(*saDir + "/ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	// ponytail: HTTP/1.1 only, so exec/attach/port-forward upgrades pass through ReverseProxy.
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{RootCAs: pool}}
	client = &http.Client{Transport: transport}

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(apiURL)
			pr.SetXForwarded() // apiserver audit logs the real client IP in sourceIPs
		},
	}

	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces" && r.URL.Query().Get("watch") == "" {
			listNamespaces(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	})
	if *accessLog {
		h = logRequests(h)
	}

	// No ReadTimeout/WriteTimeout: they would cut watches, logs -f, exec and port-forward.
	srv := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	if !*plainHTTP {
		certs := &certReloader{}
		if _, err := certs.get(nil); err != nil {
			log.Fatal(err)
		}
		srv.TLSConfig = &tls.Config{GetCertificate: certs.get, MinVersion: tls.VersionTLS12}
	}

	// SIGTERM (rollout, drain): stop accepting, let in-flight requests finish. Streams still open at the
	// deadline (watch, exec, logs -f) are cut; clients reconnect. Stays below the default 30s grace period.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		log.Print("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()

	log.Printf("orbitgate listening on %s -> %s", *listen, apiURL)
	if *plainHTTP {
		err = srv.ListenAndServe()
	} else {
		err = srv.ListenAndServeTLS("", "")
	}
	if err != http.ErrServerClosed {
		log.Fatal(err)
	}
	<-done
}

// logRequests logs one line per request. Only the path: query strings can carry secrets (exec commands).
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start, sw := time.Now(), &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.code == 0 && r.Header.Get("Upgrade") != "" {
			sw.code = http.StatusSwitchingProtocols // hijacked: exec, attach, port-forward
		}
		log.Printf("%s %s %s %d %s", r.RemoteAddr, r.Method, r.URL.Path, sw.code, time.Since(start).Round(time.Millisecond))
	})
}

// statusWriter records the status code. Unwrap keeps Flush/Hijack working via http.ResponseController.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.code == 0 {
		s.code = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// certReloader re-reads the cert when the file changes, so cert-manager/secret
// rotation is picked up without a restart. Mount the secret as a directory, not
// subPath: subPath mounts never update.
// ponytail: one stat per TLS handshake; fine at kubectl rates.
type certReloader struct {
	mu   sync.Mutex
	mod  time.Time
	cert *tls.Certificate
}

func (c *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := os.Stat(*tlsCert)
	if err == nil && c.cert != nil && st.ModTime().Equal(c.mod) {
		return c.cert, nil
	}
	if err == nil {
		var cert tls.Certificate
		if cert, err = tls.LoadX509KeyPair(*tlsCert, *tlsKey); err == nil {
			c.cert, c.mod = &cert, st.ModTime()
			log.Printf("loaded TLS cert %q, expires %s", cert.Leaf.Subject.CommonName, cert.Leaf.NotAfter.Format(time.RFC3339))
			return c.cert, nil
		}
	}
	if c.cert != nil { // mid-rotation or transient: keep serving the last good cert
		log.Printf("TLS reload failed, keeping current cert: %v", err)
		return c.cert, nil
	}
	return nil, err
}

// saToken re-reads the projected token every call; kubelet rotates it.
func saToken() string {
	b, err := os.ReadFile(*saDir + "/token")
	if err != nil {
		log.Printf("read SA token: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// userAuth copies the caller's credentials (and any Impersonate-* the apiserver will judge) onto req.
func userAuth(req *http.Request, from http.Header) {
	for k, v := range from {
		if k == "Authorization" || strings.HasPrefix(k, "Impersonate-") {
			req.Header[k] = v
		}
	}
}

// listNamespaces first asks the apiserver as the user. Allowed (e.g. cluster-admin):
// the real answer passes through untouched. Forbidden: list with the proxy SA and keep
// only namespaces where the user can list pods (asked as the user, via SelfSubjectAccessReview).
func listNamespaces(w http.ResponseWriter, r *http.Request) {
	target := apiURL.JoinPath(r.URL.Path).String() + "?" + r.URL.RawQuery
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	req.Header = r.Header.Clone()
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusForbidden {
		relay(w, resp)
		return
	}
	resp.Body.Close()

	accept := r.Header.Get("Accept")
	if accept == "" || strings.Contains(accept, "protobuf") {
		accept = "application/json" // we have to decode it to filter
	}
	req, _ = http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	req.Header.Set("Accept", accept)
	req.Header.Set("Authorization", "Bearer "+saToken())
	if resp, err = client.Do(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		relay(w, resp)
		return
	}

	var body map[string]any
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	filter(body, allowedNamespaces(r.Context(), r.Header, names(body)))
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	json.NewEncoder(w).Encode(body)
}

func relay(w http.ResponseWriter, resp *http.Response) {
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// entries returns the list key and its entries: "items" for NamespaceList, "rows" for Table (kubectl get).
func entries(body map[string]any) (string, []any) {
	for _, k := range []string{"items", "rows"} {
		if l, ok := body[k].([]any); ok {
			return k, l
		}
	}
	return "", nil
}

func nameOf(e any) string {
	m, _ := e.(map[string]any)
	if obj, ok := m["object"].(map[string]any); ok { // Table row
		m = obj
	}
	meta, _ := m["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	return name
}

func names(body map[string]any) []string {
	_, l := entries(body)
	var out []string
	for _, e := range l {
		if n := nameOf(e); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// filter keeps only allowed entries; anything without a name (e.g. Table with includeObject=None) is dropped.
func filter(body map[string]any, allowed map[string]bool) {
	k, l := entries(body)
	if k == "" {
		return
	}
	kept := []any{}
	for _, e := range l {
		if allowed[nameOf(e)] {
			kept = append(kept, e)
		}
	}
	body[k] = kept
	if meta, ok := body["metadata"].(map[string]any); ok {
		delete(meta, "remainingItemCount") // would leak the real namespace count
	}
}

// ponytail: one SelfSubjectAccessReview per namespace, 16 in flight. Cache per (token, ns) if clusters get big.
func allowedNamespaces(ctx context.Context, user http.Header, nss []string) map[string]bool {
	allowed := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, ns := range nss {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			ok, err := canSeeNamespace(ctx, user, ns)
			if err != nil {
				log.Printf("SSAR %s: %v", ns, err) // fail closed
			}
			mu.Lock()
			allowed[ns] = ok
			mu.Unlock()
		}()
	}
	wg.Wait()
	return allowed
}

// ponytail: "can list pods" = tenant of that namespace. view/edit/admin all grant it,
// unlike "get namespace" for custom roles. Make it a flag if a tenant role ever lacks pods.
func canSeeNamespace(ctx context.Context, user http.Header, ns string) (bool, error) {
	b, _ := json.Marshal(map[string]any{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SelfSubjectAccessReview",
		"spec":       map[string]any{"resourceAttributes": map[string]string{"verb": "list", "resource": "pods", "namespace": ns}},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, apiURL.JoinPath("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews").String(), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	userAuth(req, user)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("status %s", resp.Status)
	}
	var out struct {
		Status struct{ Allowed bool } `json:"status"`
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	return err == nil && out.Status.Allowed, err
}
