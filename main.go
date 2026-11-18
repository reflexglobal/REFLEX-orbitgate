// orbitgate: OIDC-authenticating kube-apiserver proxy that impersonates the
// caller and only lists the namespaces the caller has RBAC access to.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
)

var (
	listen      = flag.String("listen", ":8443", "listen address")
	tlsCert     = flag.String("tls-cert", "", "TLS cert file")
	tlsKey      = flag.String("tls-key", "", "TLS key file")
	plainHTTP   = flag.Bool("plain-http", false, "serve plain HTTP (only behind a TLS-terminating LB/ingress)")
	apiserver   = flag.String("apiserver", "https://kubernetes.default.svc", "kube-apiserver URL")
	saDir       = flag.String("sa-dir", "/var/run/secrets/kubernetes.io/serviceaccount", "dir with token + ca.crt")
	issuer      = flag.String("issuer", "", "OIDC issuer URL")
	clientID    = flag.String("client-id", "", "OIDC client ID (token audience)")
	userClaim   = flag.String("username-claim", "email", "claim used as Kubernetes username")
	groupsClaim = flag.String("groups-claim", "groups", "claim used as Kubernetes groups")
	prefix      = flag.String("prefix", "oidc:", "prefix for usernames and groups (keep it, see README)")
)

var (
	apiURL   *url.URL
	client   *http.Client
	verifier *oidc.IDTokenVerifier
)

type identity struct {
	user   string
	groups []string
}

func main() {
	flag.Parse()
	if *issuer == "" || *clientID == "" {
		log.Fatal("-issuer and -client-id are required")
	}
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

	provider, err := oidc.NewProvider(context.Background(), *issuer)
	if err != nil {
		log.Fatal(err)
	}
	verifier = provider.Verifier(&oidc.Config{ClientID: *clientID})

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(apiURL)
			pr.Out.Header.Set("Authorization", "Bearer "+saToken())
		},
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := authenticate(r)
		if err != nil {
			log.Printf("auth failed from %s: %v", r.RemoteAddr, err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces" && r.URL.Query().Get("watch") == "" {
			listNamespaces(w, r, id)
			return
		}
		impersonate(r.Header, id)
		proxy.ServeHTTP(w, r)
	})

	log.Printf("orbitgate listening on %s -> %s", *listen, apiURL)
	if *plainHTTP {
		log.Fatal(http.ListenAndServe(*listen, h))
	}
	log.Fatal(http.ListenAndServeTLS(*listen, *tlsCert, *tlsKey, h))
}

// saToken re-reads the projected token every call; kubelet rotates it.
func saToken() string {
	b, err := os.ReadFile(*saDir + "/token")
	if err != nil {
		log.Printf("read SA token: %v", err)
	}
	return strings.TrimSpace(string(b))
}

func authenticate(r *http.Request) (identity, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return identity{}, errors.New("no bearer token")
	}
	tok, err := verifier.Verify(r.Context(), raw)
	if err != nil {
		return identity{}, err
	}
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return identity{}, err
	}
	return identityFromClaims(claims)
}

func identityFromClaims(claims map[string]any) (identity, error) {
	user, _ := claims[*userClaim].(string)
	if user == "" {
		return identity{}, fmt.Errorf("claim %q missing", *userClaim)
	}
	id := identity{user: *prefix + user}
	if gs, ok := claims[*groupsClaim].([]any); ok {
		for _, g := range gs {
			if s, ok := g.(string); ok && s != "" {
				id.groups = append(id.groups, *prefix+s)
			}
		}
	}
	// Never let a token claim impersonate system:masters & co, even with -prefix="".
	for _, n := range append([]string{id.user}, id.groups...) {
		if strings.HasPrefix(n, "system:") {
			return identity{}, fmt.Errorf("refusing reserved name %q", n)
		}
	}
	return id, nil
}

// impersonate drops caller credentials and any caller-supplied Impersonate-*
// headers (the proxy SA may impersonate anyone), then sets the verified identity.
func impersonate(h http.Header, id identity) {
	h.Del("Authorization")
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "impersonate-") {
			delete(h, k)
		}
	}
	h.Set("Impersonate-User", id.user)
	for _, g := range id.groups {
		h.Add("Impersonate-Group", g)
	}
}

// listNamespaces lists as the proxy SA, then keeps only namespaces the caller can list pods in.
func listNamespaces(w http.ResponseWriter, r *http.Request, id identity) {
	accept := r.Header.Get("Accept")
	if accept == "" || strings.Contains(accept, "protobuf") {
		accept = "application/json" // we have to decode it to filter
	}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL.JoinPath(r.URL.Path).String()+"?"+r.URL.RawQuery, nil)
	req.Header.Set("Accept", accept)
	req.Header.Set("Authorization", "Bearer "+saToken())
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	var body map[string]any
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	filter(body, allowedNamespaces(r.Context(), id, names(body)))

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	json.NewEncoder(w).Encode(body)
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

// ponytail: one SubjectAccessReview per namespace, 16 in flight. Cache per (user, ns) if clusters get big.
func allowedNamespaces(ctx context.Context, id identity, nss []string) map[string]bool {
	allowed := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, ns := range nss {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			ok, err := canSeeNamespace(ctx, id, ns)
			if err != nil {
				log.Printf("SAR %s/%s: %v", id.user, ns, err) // fail closed
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
// unlike "get namespace". Make it a flag if a tenant role ever lacks pods.
func canSeeNamespace(ctx context.Context, id identity, ns string) (bool, error) {
	sar := map[string]any{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SubjectAccessReview",
		"spec": map[string]any{
			"user":   id.user,
			"groups": append([]string{"system:authenticated"}, id.groups...),
			"resourceAttributes": map[string]string{"verb": "list", "resource": "pods", "namespace": ns},
		},
	}
	b, _ := json.Marshal(sar)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, apiURL.JoinPath("/apis/authorization.k8s.io/v1/subjectaccessreviews").String(), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+saToken())
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
