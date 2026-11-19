// Copyright (c) 2026 REFLEX GLOBAL B.V.
// SPDX-License-Identifier: MIT

// Orbitgate: a pass-through kube-apiserver proxy that only lists the namespaces
// a user has access to. Authentication, RBAC, admission and audit stay with the
// apiserver: user credentials are forwarded untouched.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	listen      = flag.String("listen", ":8443", "listen address")
	tlsCert     = flag.String("tls-cert", "", "TLS cert file (reloaded on change)")
	tlsKey      = flag.String("tls-key", "", "TLS key file")
	plainHTTP   = flag.Bool("plain-http", false, "serve plain HTTP (only behind a TLS-terminating LB/ingress)")
	apiserver   = flag.String("apiserver", "https://kubernetes.default.svc", "kube-apiserver URL")
	saDir       = flag.String("sa-dir", "/var/run/secrets/kubernetes.io/serviceaccount", "dir with token + ca.crt")
	apiCAFile   = flag.String("apiserver-ca", "", "CA bundle that signed the apiserver cert, reloaded on change (default: <sa-dir>/ca.crt)")
	ownCert     = flag.String("client-cert", "", "own client cert for listing namespaces, instead of the ServiceAccount token (reloaded on change)")
	ownKey      = flag.String("client-key", "", "key for -client-cert")
	printVer    = flag.Bool("version", false, "print the version and exit")
	tenantVerb  = flag.String("tenant-verb", "list", "tenant check: verb a user needs in a namespace to see it in the list")
	tenantRes   = flag.String("tenant-resource", "pods", "tenant check: resource for -tenant-verb")
	tenantGroup = flag.String("tenant-group", "", "tenant check: API group of -tenant-resource (empty = core)")
	metricsAddr = flag.String("metrics-listen", "", "plain-HTTP listener for /metrics, /healthz, /readyz (e.g. :9090; empty = off)")
	accessLog   = flag.Bool("access-log", false, "log every request: client IP, method, path, status, duration (never credentials)")
	accessJSON  = flag.Bool("access-log-json", false, "with -access-log: JSON lines that add the caller's user/groups (SelfSubjectReview, cached), verb, namespace, resource")
	trustedIss  = flag.String("trusted-issuers", "", "comma-separated token issuers the apiserver trusts; only used to explain a 401 (the apiserver still decides)")
)

var version = "dev" // set at build time: -ldflags "-X main.version=X.Y.Z"

var (
	apiURL *url.URL
	client *http.Client // carries only the user's credentials
	own    *http.Client // Orbitgate's own client cert (-client-cert); nil = ServiceAccount token, see ownDo
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
	if (*ownCert == "") != (*ownKey == "") {
		log.Fatal("-client-cert and -client-key go together")
	}

	var err error
	if apiURL, err = url.Parse(*apiserver); err != nil {
		log.Fatal(err)
	}
	if _, err := apiCA.get(); err != nil {
		log.Fatal(err)
	}
	transport := newTransport()
	client = &http.Client{Transport: transport}
	if *ownCert != "" {
		if own, err = ownClient(transport); err != nil {
			log.Fatal(err)
		}
	}

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(apiURL)
			pr.SetXForwarded() // apiserver audit logs the real client IP in sourceIPs
		},
		ModifyResponse: explain401,
	}

	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces" {
			listNamespaces(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	})
	h = observe(h)
	if *metricsAddr != "" {
		go func() {
			srv := &http.Server{Addr: *metricsAddr, Handler: metricsMux(), ReadHeaderTimeout: 10 * time.Second}
			log.Fatal(srv.ListenAndServe())
		}()
	}

	// No ReadTimeout/WriteTimeout: they would cut watches, logs -f, exec and port-forward.
	srv := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	if !*plainHTTP {
		certs := &certReloader{certFile: *tlsCert, keyFile: *tlsKey, metric: "orbitgate_tls_cert_expiry_timestamp_seconds"}
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

// observe counts requests by status and, with -access-log, logs one line per request.
// Only the path: query strings can carry secrets (exec commands).
func observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start, sw := time.Now(), &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.code == 0 && r.Header.Get("Upgrade") != "" {
			sw.code = http.StatusSwitchingProtocols // hijacked: exec, attach, port-forward
		}
		inc(fmt.Sprintf("orbitgate_requests_total{code=%q}", strconv.Itoa(sw.code)))
		if !*accessLog {
			return
		}
		if *accessJSON {
			go logJSON(r.RemoteAddr, r.Method, r.URL, r.Header.Clone(), sw.code, time.Since(start)) // identity lookup off the request path
			return
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
	certFile, keyFile, metric string
	mu                        sync.Mutex
	mod                       time.Time
	cert                      *tls.Certificate
}

func (c *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := os.Stat(c.certFile)
	if err == nil && c.cert != nil && st.ModTime().Equal(c.mod) {
		return c.cert, nil
	}
	if err == nil {
		var cert tls.Certificate
		if cert, err = tls.LoadX509KeyPair(c.certFile, c.keyFile); err == nil {
			c.cert, c.mod = &cert, st.ModTime()
			set(c.metric, float64(cert.Leaf.NotAfter.Unix()))
			log.Printf("loaded TLS cert %q, expires %s", cert.Leaf.Subject.CommonName, cert.Leaf.NotAfter.Format(time.RFC3339))
			return c.cert, nil
		}
	}
	if c.cert != nil { // mid-rotation or transient: keep serving the last good cert
		log.Printf("TLS reload failed for %s, keeping current cert: %v", c.certFile, err)
		return c.cert, nil
	}
	return nil, err
}

// newTransport is http.DefaultTransport (dial/TLS/idle timeouts, proxy env) with the apiserver CA.
// ponytail: HTTP/1.1 only, so exec/attach/port-forward upgrades pass through ReverseProxy.
func newTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ForceAttemptHTTP2 = false
	t.MaxIdleConnsPerHost = 100 // default 2: most requests would open a new TLS conn under load
	// Standard chain verification against the current CA (VerifyConnection runs for every
	// handshake); InsecureSkipVerify only turns off the static RootCAs check it replaces.
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, VerifyConnection: apiCA.verify}
	return t
}

// ownClient presents Orbitgate's client cert, on its own transport. Never on the one that
// forwards user requests: the apiserver would authenticate those as Orbitgate (x509 wins over tokens).
func ownClient(user *http.Transport) (*http.Client, error) {
	certs := &certReloader{certFile: *ownCert, keyFile: *ownKey, metric: "orbitgate_client_cert_expiry_timestamp_seconds"}
	if _, err := certs.get(nil); err != nil {
		return nil, err
	}
	t := user.Clone() // idle conns close after 90s, so a renewed cert is used soon after the file changes
	t.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return certs.get(nil) }
	return &http.Client{Transport: t}, nil
}

// ownDo sends req as Orbitgate itself: the client cert if set, else the ServiceAccount token.
func ownDo(req *http.Request) (*http.Response, error) {
	if own != nil {
		return own.Do(req)
	}
	req.Header.Set("Authorization", "Bearer "+saToken())
	return client.Do(req)
}

var apiCA = &caReloader{}

// caReloader re-reads the apiserver CA (ca.crt) when it changes, so a cluster CA
// rotation needs no restart. Same idea as certReloader: one stat per handshake.
type caReloader struct {
	mu   sync.Mutex
	mod  time.Time
	pool *x509.CertPool
}

func (c *caReloader) get() (*x509.CertPool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f := *apiCAFile
	if f == "" {
		f = *saDir + "/ca.crt"
	}
	st, err := os.Stat(f)
	if err == nil && c.pool != nil && st.ModTime().Equal(c.mod) {
		return c.pool, nil
	}
	var b []byte
	if err == nil {
		b, err = os.ReadFile(f)
	}
	if err == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(b) {
			if c.pool != nil {
				log.Printf("reloaded apiserver CA %s", f)
			}
			c.pool, c.mod = pool, st.ModTime()
			return c.pool, nil
		}
		err = fmt.Errorf("no certificates in %s", f)
	}
	if c.pool != nil { // mid-rotation or transient: keep the last good CA
		log.Printf("CA reload failed, keeping current CA: %v", err)
		return c.pool, nil
	}
	return nil, err
}

func (c *caReloader) verify(cs tls.ConnectionState) error {
	pool, err := c.get()
	if err != nil {
		return err
	}
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("apiserver sent no certificate")
	}
	opts := x509.VerifyOptions{Roots: pool, DNSName: cs.ServerName, Intermediates: x509.NewCertPool()}
	for _, ic := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(ic)
	}
	_, err = cs.PeerCertificates[0].Verify(opts)
	return err
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
		if isCred(k) {
			req.Header[k] = v
		}
	}
}

func isCred(k string) bool { return k == "Authorization" || strings.HasPrefix(k, "Impersonate-") }

// listNamespaces first asks the apiserver as the user. Allowed (e.g. cluster-admin):
// the real answer passes through untouched. Forbidden: list as Orbitgate itself and keep
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
		inc(`orbitgate_namespace_requests_total{mode="passthrough"}`)
		explain401(resp)
		relay(w, resp)
		return
	}
	inc(`orbitgate_namespace_requests_total{mode="filtered"}`)
	resp.Body.Close()

	accept := r.Header.Get("Accept")
	if accept == "" || strings.Contains(accept, "protobuf") {
		accept = "application/json" // we have to decode it to filter
	}
	// No pagination when filtering: a continue token encodes the page's last namespace name
	// (base64 JSON), so ?limit=1 would let a tenant walk every name. Lists are small; take them whole.
	q := r.URL.Query()
	q.Del("limit")
	q.Del("continue")
	req, _ = http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL.JoinPath(r.URL.Path).String()+"?"+q.Encode(), nil)
	req.Header.Set("Accept", accept)
	if resp, err = ownDo(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		relay(w, resp)
		return
	}
	if isWatch(r.URL.Query()) {
		watchNamespaces(w, r, resp)
		return
	}

	var body map[string]any
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if k, _ := entries(body); k == "" { // not a list: fail closed rather than pass it through unfiltered
		http.Error(w, "unexpected namespace list response", http.StatusBadGateway)
		return
	}
	filter(body, allowedNamespaces(r.Context(), r.Header, names(body)))
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	json.NewEncoder(w).Encode(body)
}

// explain401 replaces the apiserver's bare "Unauthorized" with the reason, read from the token's
// unverified claims, and logs it. Diagnostic only: the apiserver already said no, Orbitgate decides nothing.
// Never the token itself: only issuer, audience and expiry.
func explain401(resp *http.Response) error {
	if resp.StatusCode != http.StatusUnauthorized || resp.Request == nil {
		return nil
	}
	why := tokenReason(resp.Request.Header.Get("Authorization"), time.Now())
	log.Printf("apiserver rejected credentials: %s", why)
	b, _ := json.Marshal(map[string]any{"kind": "Status", "apiVersion": "v1", "metadata": map[string]any{},
		"status": "Failure", "message": "Unauthorized: " + why, "reason": "Unauthorized", "code": http.StatusUnauthorized})
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Del("Content-Encoding")
	return nil
}

// tokenReason guesses why the apiserver rejected auth: untrusted issuer (needs -trusted-issuers), expiry, or neither.
func tokenReason(auth string, now time.Time) string {
	tok, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || tok == "" {
		return "no bearer token (client certificates do not pass through Orbitgate)"
	}
	parts := strings.Split(tok, ".")
	var c struct {
		Iss string `json:"iss"`
		Aud any    `json:"aud"`
		Exp int64  `json:"exp"`
	}
	if len(parts) != 3 {
		return "the apiserver rejected the token (not a JWT)"
	}
	if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil || json.Unmarshal(b, &c) != nil {
		return "the apiserver rejected the token (unreadable JWT claims)"
	}
	iss := clean(c.Iss)
	if trusted := issuers(); len(trusted) > 0 && !slices.Contains(trusted, c.Iss) {
		return fmt.Sprintf("token issuer %s is not trusted; trusted: %s", iss, strings.Join(trusted, ", "))
	}
	if c.Exp > 0 && now.Unix() >= c.Exp {
		return fmt.Sprintf("token from issuer %s expired at %s", iss, time.Unix(c.Exp, 0).UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf("the apiserver rejected the token from issuer %s, audience %s (check its issuer, audience and claim rules)", iss, clean(fmt.Sprint(c.Aud)))
}

func issuers() (out []string) {
	for s := range strings.SplitSeq(*trustedIss, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return
}

// clean makes a caller-supplied claim safe for a log line: no control characters, at most 200 bytes.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	if s == "" {
		s = "(none)"
	}
	return s
}

// relay copies resp to w minus hop-by-hop headers (RFC 9110 7.6.1), like httputil.ReverseProxy does.
func relay(w http.ResponseWriter, resp *http.Response) {
	defer resp.Body.Close()
	h := resp.Header.Clone()
	for _, v := range h.Values("Connection") {
		for f := range strings.SplitSeq(v, ",") {
			h.Del(strings.TrimSpace(f))
		}
	}
	for _, k := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(k)
	}
	maps.Copy(w.Header(), h)
	w.WriteHeader(resp.StatusCode)
	io.Copy(flushWriter{w}, resp.Body) // flush per chunk: passthrough watches must stream
}

type flushWriter struct{ w http.ResponseWriter }

func (f flushWriter) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	http.NewResponseController(f.w).Flush()
	return n, err
}

// isWatch parses ?watch= like the apiserver: only "0" and "false" are false, even an empty value is true.
func isWatch(q url.Values) bool {
	v, ok := q["watch"]
	return ok && len(v) > 0 && v[0] != "0" && !strings.EqualFold(v[0], "false")
}

// watchNamespaces streams Orbitgate's own namespace watch, forwarding only events the user may see.
// Each event is checked when it arrives (SSARs cached, see ssarTTL), so RBAC changes apply mid-watch.
func watchNamespaces(w http.ResponseWriter, r *http.Request, resp *http.Response) {
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	rc := http.NewResponseController(w)
	rc.Flush()
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	enc := json.NewEncoder(w)
	for {
		var ev map[string]any
		if dec.Decode(&ev) != nil {
			return
		}
		if visibleEvent(r.Context(), r.Header, ev) {
			if enc.Encode(ev) != nil || rc.Flush() != nil {
				return
			}
		}
	}
}

// visibleEvent fails closed: only events for allowed namespaces, nameless BOOKMARKs and Status errors pass.
func visibleEvent(ctx context.Context, user http.Header, ev map[string]any) bool {
	obj, _ := ev["object"].(map[string]any)
	if obj == nil {
		return false
	}
	if obj["kind"] == "Status" {
		return true
	}
	if obj["kind"] == "Table" { // kubectl get ns -w
		filter(obj, allowedNamespaces(ctx, user, names(obj)))
		_, l := entries(obj)
		return len(l) > 0
	}
	if n := nameOf(obj); n != "" {
		return allowedNamespaces(ctx, user, []string{n})[n]
	}
	return ev["type"] == "BOOKMARK"
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
		delete(meta, "continue")           // would leak a namespace name (see listNamespaces)
	}
}

// SSAR results are cached per (credentials, namespace) for ssarTTL, and at most 32 SSARs are in
// flight across all requests, so a tenant looping `get ns` can't multiply apiserver load.
// Trade-off: a granted/revoked binding shows up in the namespace list up to ssarTTL late.
const ssarTTL = 30 * time.Second

type ssarKey struct {
	cred [32]byte
	ns   string
}

type ssarResult struct {
	ok  bool
	exp time.Time
}

var (
	ssarSlots = make(chan struct{}, 32)
	ssarMu    sync.Mutex
	ssarCache = map[ssarKey]ssarResult{}
	ssarSwept time.Time
)

// credKey identifies the caller by everything userAuth forwards (token + Impersonate-*).
func credKey(h http.Header) [32]byte {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(h)) {
		if isCred(k) {
			fmt.Fprintf(&b, "%s=%q\n", k, h[k])
		}
	}
	return sha256.Sum256([]byte(b.String()))
}

func cachedSSAR(k ssarKey) (ok, hit bool) {
	ssarMu.Lock()
	defer ssarMu.Unlock()
	r, hit := ssarCache[k]
	return r.ok, hit && time.Now().Before(r.exp)
}

func storeSSAR(k ssarKey, ok bool) {
	ssarMu.Lock()
	defer ssarMu.Unlock()
	now := time.Now()
	ssarCache[k] = ssarResult{ok, now.Add(ssarTTL)}
	if now.Sub(ssarSwept) > ssarTTL { // ponytail: full sweep once per TTL; size is bounded by request rate
		for k, r := range ssarCache {
			if now.After(r.exp) {
				delete(ssarCache, k)
			}
		}
		ssarSwept = now
	}
}

func allowedNamespaces(ctx context.Context, user http.Header, nss []string) map[string]bool {
	cred := credKey(user)
	allowed := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	defer wg.Wait()
	for _, ns := range nss {
		k := ssarKey{cred, ns}
		if ok, hit := cachedSSAR(k); hit {
			inc("orbitgate_ssar_cache_hits_total")
			mu.Lock()
			allowed[ns] = ok
			mu.Unlock()
			continue
		}
		select {
		case ssarSlots <- struct{}{}:
		case <-ctx.Done(): // client gone; unchecked namespaces stay hidden
			return allowed
		}
		wg.Add(1)
		go func() {
			defer func() { <-ssarSlots; wg.Done() }()
			ok, err := canSeeNamespace(ctx, user, ns)
			inc("orbitgate_ssar_total")
			if err != nil {
				inc("orbitgate_ssar_errors_total")
				log.Printf("SSAR %s: %v", ns, err) // fail closed, not cached
			} else {
				storeSSAR(k, ok)
			}
			mu.Lock()
			allowed[ns] = ok
			mu.Unlock()
		}()
	}
	return allowed
}

// Tenant of a namespace = allowed -tenant-verb on -tenant-resource there (default "list pods":
// view/edit/admin all grant it, unlike "get namespace" for custom roles).
// ponytail: one check; OR over several checks if a single resource ever doesn't fit all tenants.
func canSeeNamespace(ctx context.Context, user http.Header, ns string) (bool, error) {
	b, _ := json.Marshal(map[string]any{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SelfSubjectAccessReview",
		"spec": map[string]any{"resourceAttributes": map[string]string{
			"verb": *tenantVerb, "resource": *tenantRes, "group": *tenantGroup, "namespace": ns,
		}},
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

// Metrics in the Prometheus text format, stdlib only. Keys are full series names.
var metrics = struct {
	sync.Mutex
	m map[string]float64
}{m: map[string]float64{}}

func inc(series string) {
	metrics.Lock()
	metrics.m[series]++
	metrics.Unlock()
}

func set(series string, v float64) {
	metrics.Lock()
	metrics.m[series] = v
	metrics.Unlock()
}

func metricsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	// Ready = the apiserver answers (the serving cert is loaded before the listener starts).
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.JoinPath("/readyz").String(), nil)
		resp, err := ownDo(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				err = fmt.Errorf("apiserver /readyz: %s", resp.Status)
			}
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		metrics.Lock()
		defer metrics.Unlock()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		prev := ""
		for _, k := range slices.Sorted(maps.Keys(metrics.m)) {
			if name, _, _ := strings.Cut(k, "{"); name != prev {
				typ := map[bool]string{true: "counter", false: "gauge"}[strings.HasSuffix(name, "_total")]
				fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
				prev = name
			}
			fmt.Fprintf(w, "%s %s\n", k, strconv.FormatFloat(metrics.m[k], 'f', -1, 64))
		}
	})
	return mux
}

var jsonLog = slog.New(slog.NewJSONHandler(os.Stderr, nil))

func logJSON(client, method string, u *url.URL, h http.Header, code int, d time.Duration) {
	ri := parseRequest(method, u)
	attrs := []any{"client", client, "method", method, "path", u.Path, "verb", ri.verb, "apiGroup", ri.group,
		"namespace", ri.namespace, "resource", ri.resource, "subresource", ri.subresource, "name", ri.name,
		"code", code, "allowed", code != http.StatusUnauthorized && code != http.StatusForbidden, "durationMs", d.Milliseconds()}
	if code != http.StatusUnauthorized {
		if who, err := whoami(h); err != nil {
			attrs = append(attrs, "identityError", err.Error())
		} else {
			attrs = append(attrs, "user", who.Username, "groups", who.Groups)
		}
	}
	jsonLog.Info("request", attrs...)
}

type reqInfo struct{ verb, group, namespace, resource, subresource, name string }

// parseRequest is a small version of the apiserver's RequestInfo: enough for a log line, not for decisions.
func parseRequest(method string, u *url.URL) (ri reqInfo) {
	p := strings.Split(strings.Trim(u.Path, "/"), "/")
	switch {
	case len(p) >= 2 && p[0] == "api":
		p = p[2:]
	case len(p) >= 3 && p[0] == "apis":
		ri.group, p = p[1], p[3:]
	default: // non-resource URL: /version, /healthz, discovery
		ri.verb = strings.ToLower(method)
		return
	}
	if len(p) >= 2 && p[0] == "namespaces" {
		ri.namespace = p[1]
		if len(p) > 2 && p[2] != "status" && p[2] != "finalize" { // namespaces/x/status is the namespace's own subresource
			p = p[2:]
		}
	}
	for i, f := range []*string{&ri.resource, &ri.name, &ri.subresource} {
		if i < len(p) {
			*f = p[i]
		}
	}
	switch method {
	case http.MethodGet, http.MethodHead:
		ri.verb = map[bool]string{true: "get", false: "list"}[ri.name != ""]
		if isWatch(u.Query()) {
			ri.verb = "watch"
		}
	case http.MethodPost:
		ri.verb = "create"
	case http.MethodPut:
		ri.verb = "update"
	case http.MethodPatch:
		ri.verb = "patch"
	case http.MethodDelete:
		ri.verb = map[bool]string{true: "delete", false: "deletecollection"}[ri.name != ""]
	default:
		ri.verb = strings.ToLower(method)
	}
	return
}

type userInfo struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

type whoResult struct {
	u   userInfo
	exp time.Time
}

var whoCache = map[[32]byte]whoResult{} // guarded by ssarMu

// whoami asks the apiserver who the caller is (SelfSubjectReview, GA in 1.28), cached per credential for ssarTTL.
func whoami(h http.Header) (userInfo, error) {
	k := credKey(h)
	ssarMu.Lock()
	r, hit := whoCache[k]
	ssarMu.Unlock()
	if hit && time.Now().Before(r.exp) {
		return r.u, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, apiURL.JoinPath("/apis/authentication.k8s.io/v1/selfsubjectreviews").String(),
		strings.NewReader(`{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}`))
	req.Header.Set("Content-Type", "application/json")
	userAuth(req, h)
	resp, err := client.Do(req)
	if err != nil {
		return userInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return userInfo{}, fmt.Errorf("SelfSubjectReview: %s", resp.Status)
	}
	var out struct {
		Status struct {
			UserInfo userInfo `json:"userInfo"`
		} `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return userInfo{}, err
	}
	ssarMu.Lock()
	if len(whoCache) > 10000 { // ponytail: drop everything at the cap; entries refill on demand
		clear(whoCache)
	}
	whoCache[k] = whoResult{out.Status.UserInfo, time.Now().Add(ssarTTL)}
	ssarMu.Unlock()
	return out.Status.UserInfo, nil
}
