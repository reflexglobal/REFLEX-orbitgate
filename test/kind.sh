#!/usr/bin/env bash
# Copyright (c) 2026 REFLEX GLOBAL B.V.
# SPDX-License-Identifier: MIT
# Own kind cluster "orbitgate" (audit logging on) + Orbitgate via the Helm chart, then e2e through the proxy.
# Users are ServiceAccount tokens: Orbitgate passes any credential the apiserver accepts (OIDC works the same).
# Re-runnable. Teardown: kind delete cluster --name ${KIND_CLUSTER:-orbitgate} --kubeconfig test/.kubeconfig
set -euo pipefail
cd "$(dirname "$0")/.."
C=${KIND_CLUSTER:-orbitgate}  # override to run next to other kind clusters
export KUBECONFIG=$PWD/test/.kubeconfig  # own kubeconfig: never touches ~/.kube/config or its current context
tmp=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$tmp"' EXIT

kind get clusters | grep -qx "$C" || kind create cluster --name "$C" --kubeconfig "$KUBECONFIG" --config test/kind-config.yaml
kubectl config use-context "kind-$C" >/dev/null  # pinned, even within the own kubeconfig
docker build -q -t orbitgate:dev . >/dev/null
kind load docker-image orbitgate:dev --name "$C"

# Bring-your-own cert, same steps as docs/TLS.md: own CA + leaf with SANs.
openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj "/CN=Orbitgate test CA" \
  -keyout "$tmp/ca.key" -out "$tmp/ca.crt" 2>/dev/null
openssl req -newkey rsa:3072 -nodes -subj /CN=orbitgate -keyout "$tmp/tls.key" -out "$tmp/tls.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > "$tmp/ext"
openssl x509 -req -in "$tmp/tls.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -CAcreateserial \
  -days 365 -extfile "$tmp/ext" -out "$tmp/tls.crt" 2>/dev/null

kubectl create ns orbitgate --dry-run=client -o yaml | kubectl apply -f - >/dev/null
helm upgrade --install orbitgate charts/orbitgate -n orbitgate \
  --set image.repository=orbitgate --set image.tag=dev --set tls.certManager.enabled=false \
  --set networkPolicy.enabled=true --set 'extraArgs={-access-log,-access-log-json}' >/dev/null  # first: drops a cert-manager Certificate left by a previous run
kubectl -n orbitgate create secret tls orbitgate-tls --cert="$tmp/tls.crt" --key="$tmp/tls.key" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n orbitgate rollout restart deploy/orbitgate >/dev/null  # pick up the rebuilt :dev image
kubectl -n orbitgate rollout status deploy/orbitgate --timeout=120s

# Tenants. alice/bob/admin are ServiceAccounts in "users"; only RBAC decides what they see.
for ns in users dev-a dev-b; do kubectl create ns "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null; done
for u in alice bob admin; do kubectl -n users create sa "$u" --dry-run=client -o yaml | kubectl apply -f - >/dev/null; done
kubectl -n dev-a create rolebinding alice --clusterrole=edit --serviceaccount=users:alice --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n dev-b create rolebinding bob --clusterrole=edit --serviceaccount=users:bob --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create clusterrolebinding orbitgate-test-admin --clusterrole=cluster-admin --serviceaccount=users:admin --dry-run=client -o yaml | kubectl apply -f - >/dev/null
sleep 3  # RBAC informer lag

pf() { [ -n "${pfpid:-}" ] && kill "$pfpid"; kubectl -n orbitgate port-forward svc/orbitgate 18443:443 >/dev/null & pfpid=$!; sleep 2; }
pf

token() { kubectl -n users create token "$1"; }
og() { local t=$1; shift; KUBECONFIG=/dev/null kubectl --server=https://localhost:18443 --certificate-authority="$tmp/ca.crt" --token="$t" "$@"; }
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2' want '$3'"; fail=1; fi; }
nss() { og "$1" get ns -o name | tr '\n' ' ' | sed 's/ $//'; }

admin=$(token admin); alice=$(token alice); bob=$(token bob)
pod=$(kubectl -n orbitgate get pods -o jsonpath='{.items[0].metadata.name}')
check "metrics: cert expiry exported" "$(kubectl get --raw "/api/v1/namespaces/orbitgate/pods/$pod:9090/proxy/metrics" | grep -c '^orbitgate_tls_cert_expiry_timestamp_seconds ')" "1"
check "alice sees only dev-a" "$(nss "$alice")" "namespace/dev-a"
check "bob sees only dev-b" "$(nss "$bob")" "namespace/dev-b"
check "admin sees all (passthrough)" "$(og "$admin" get ns -o name | grep -c .)" "$(kubectl get ns -o name | grep -c .)"
check "alice json list" "$(og "$alice" get ns -o jsonpath='{.items[*].metadata.name}')" "dev-a"
check "alice ?limit=1: whole list, no continue token (it names a namespace)" "$(og "$alice" get --raw '/api/v1/namespaces?limit=1' | grep -o '"continue":"[^"]*"\|"name":"dev-a"' | tr '\n' ' ')" '"name":"dev-a" '
og "$alice" get ns --watch-only -o name --request-timeout=10s >"$tmp/watch" 2>/dev/null & wpid=$!
sleep 3
kubectl create ns dev-c --dry-run=client -o yaml | kubectl apply -f - >/dev/null
for ns in dev-a dev-b dev-c; do kubectl label ns "$ns" e2e-watch="$RANDOM" --overwrite >/dev/null; done
wait "$wpid" || true
check "alice watch sees only dev-a" "$(sort -u "$tmp/watch")" "namespace/dev-a"
check "alice can create deployment" "$(og "$alice" -n dev-a create deployment e2e --image=busybox:1.36 --dry-run=server -o name 2>&1)" "deployment.apps/e2e"
og "$alice" -n dev-a delete pod e2e --ignore-not-found >/dev/null
og "$alice" -n dev-a run e2e --image=busybox:1.36 --restart=Never --command -- sh -c 'echo hello-log; sleep 3600' >/dev/null
og "$alice" -n dev-a wait --for=condition=Ready pod/e2e --timeout=120s >/dev/null
check "alice logs (through proxy)" "$(og "$alice" -n dev-a logs e2e)" "hello-log"
check "alice exec (upgrade through proxy)" "$(og "$alice" -n dev-a exec e2e -- echo hi 2>&1)" "hi"
check "alice denied dev-b" "$(og "$alice" -n dev-b get pods 2>&1 | grep -c Forbidden)" "1"
check "alice can't impersonate admin" "$(og "$alice" --as=system:serviceaccount:users:admin -n dev-b get pods 2>&1 | grep -c 'cannot impersonate')" "1"
jsonlog() { kubectl -n orbitgate logs -l app.kubernetes.io/name=orbitgate --tail=100000 | grep '"user":"system:serviceaccount:users:alice"' | grep -c '"verb":"create","apiGroup":"apps","namespace":"dev-a","resource":"deployments"'; }
for _ in $(seq 10); do [ "$(jsonlog)" != 0 ] && break; sleep 1; done  # --tail: with -l, kubectl defaults to 10 lines
check "json access log names alice" "$([ "$(jsonlog)" != 0 ] && echo yes)" "yes"
check "bad token rejected" "$(og garbage get ns 2>&1 | grep -c "must be logged in")" "1"

# Audit: a write through the proxy is logged as alice herself, not as Orbitgate.
probe="audit-probe-$RANDOM"
og "$alice" -n dev-a create configmap "$probe" >/dev/null
sleep 2
ev=$(docker exec "$C-control-plane" grep "\"$probe\"" /var/log/kubernetes/audit.log | grep '"verb":"create"' | tail -1)
check "audit user is alice" "$(echo "$ev" | python3 -c 'import json,sys; e=json.load(sys.stdin); print(e["user"]["username"], "impersonated" if "impersonatedUser" in e else "direct")')" "system:serviceaccount:users:alice direct"
check "audit sourceIPs has client first" "$(echo "$ev" | python3 -c 'import json,sys; s=json.load(sys.stdin)["sourceIPs"]; print(len(s)>1 and s[0]=="127.0.0.1")')" "True"

# DaemonSet on control planes with hostNetwork: listens on the node IP itself, next to the apiserver.
helm upgrade orbitgate charts/orbitgate -n orbitgate --reuse-values \
  --set kind=DaemonSet --set hostNetwork=true --set listenPort=9443 >/dev/null
kubectl -n orbitgate rollout status ds/orbitgate --timeout=120s >/dev/null
check "daemonset: one pod per control plane" "$(kubectl -n orbitgate get ds orbitgate -o jsonpath='{.status.numberReady}')" "$(kubectl get nodes -l node-role.kubernetes.io/control-plane -o name | grep -c .)"
check "daemonset: deployment gone" "$(kubectl -n orbitgate get deploy -o name | grep -c .)" "0"
check "daemonset: listens on node IP" "$(docker exec "$C-control-plane" curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $alice" https://127.0.0.1:9443/api/v1/namespaces)" "200"
pf
check "daemonset: alice sees only dev-a" "$(nss "$alice")" "namespace/dev-a"
check "daemonset: admin passthrough" "$(og "$admin" get ns -o name | grep -c .)" "$(kubectl get ns -o name | grep -c .)"
check "daemonset: exec" "$(og "$alice" -n dev-a exec e2e -- echo hi 2>&1)" "hi"

# Cert rotation from an existing in-cluster CA (tls.certManager.caSecretName): running pods must pick it up, no restart.
served() { openssl s_client -connect localhost:18443 -servername localhost </dev/null 2>/dev/null | openssl x509 -noout -serial; }
pods=$(kubectl -n orbitgate get pods -o name | sort)
before=$(served)
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.16.2/cert-manager.yaml >/dev/null
kubectl -n cert-manager rollout status deploy/cert-manager-webhook --timeout=180s >/dev/null
kubectl -n orbitgate create secret tls orbitgate-ca --cert="$tmp/ca.crt" --key="$tmp/ca.key" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
until helm upgrade orbitgate charts/orbitgate -n orbitgate --reuse-values \
  --set tls.certManager.enabled=true --set tls.certManager.caSecretName=orbitgate-ca \
  --set 'tls.certManager.dnsNames={localhost}' --set 'tls.certManager.ipAddresses={127.0.0.1}' >/dev/null 2>&1; do sleep 3; done  # webhook warm-up
kubectl -n orbitgate wait --for=condition=Ready certificate/orbitgate --timeout=120s >/dev/null
for _ in $(seq 60); do [ "$(served)" != "$before" ] && break; sleep 3; done  # kubelet syncs secret volumes every ~60s
check "rotated cert served without restart" "$([ "$(served)" != "$before" ] && echo yes)" "yes"
check "pods not restarted" "$(kubectl -n orbitgate get pods -o name | sort)" "$pods"
check "kubectl still trusts it" "$(og "$alice" get ns -o name)" "namespace/dev-a"

# Static pod without a ServiceAccount (docs/static-pod.md): own client cert minted via the CSR API
# (CN=orbitgate, no O), RBAC = list/watch namespaces only, files on the node's disk, apiserver on localhost.
openssl req -newkey rsa:3072 -nodes -subj /CN=orbitgate -keyout "$tmp/client.key" -out "$tmp/client.csr" 2>/dev/null
kubectl delete csr orbitgate-static --ignore-not-found >/dev/null
kubectl apply -f - >/dev/null <<EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata: {name: orbitgate-static}
spec:
  request: $(base64 < "$tmp/client.csr" | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 86400
  usages: [client auth]
EOF
kubectl certificate approve orbitgate-static >/dev/null
until kubectl get csr orbitgate-static -o jsonpath='{.status.certificate}' | grep -q .; do sleep 1; done
kubectl get csr orbitgate-static -o jsonpath='{.status.certificate}' | base64 -d > "$tmp/client.crt"
kubectl create clusterrole orbitgate-static --verb=list,watch --resource=namespaces --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create clusterrolebinding orbitgate-static --clusterrole=orbitgate-static --user=orbitgate --dry-run=client -o yaml | kubectl apply -f - >/dev/null
mkdir "$tmp/static"
cp "$tmp/client.crt" "$tmp/client.key" "$tmp/tls.crt" "$tmp/tls.key" "$tmp/static/"
docker exec "$C-control-plane" mkdir -p /var/lib/orbitgate
docker cp "$tmp/static/." "$C-control-plane:/var/lib/orbitgate/" >/dev/null
docker exec "$C-control-plane" sh -c "cp /etc/kubernetes/pki/ca.crt /var/lib/orbitgate/apiserver-ca.crt && chown -R 0:0 /var/lib/orbitgate"  # root-owned, as Talos writes them
run=$RANDOM
cat > "$tmp/orbitgate.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata: {name: orbitgate, namespace: kube-system, annotations: {e2e-run: "$run"}}  # new hash: kubelet recreates it on the rebuilt image
spec:
  hostNetwork: true
  containers:
    - name: orbitgate
      image: orbitgate:dev
      imagePullPolicy: Never
      args: [-listen=:9444, -apiserver=https://127.0.0.1:6443, -apiserver-ca=/certs/apiserver-ca.crt,
             -client-cert=/certs/client.crt, -client-key=/certs/client.key, -tls-cert=/certs/tls.crt, -tls-key=/certs/tls.key]
      securityContext: {runAsUser: 0, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
      volumeMounts: [{name: certs, mountPath: /certs, readOnly: true}]
  volumes: [{name: certs, hostPath: {path: /var/lib/orbitgate, type: Directory}}]
EOF
audit0=$(docker exec "$C-control-plane" sh -c "wc -l < /var/log/kubernetes/audit.log")
docker cp "$tmp/orbitgate.yaml" "$C-control-plane:/etc/kubernetes/manifests/orbitgate.yaml" >/dev/null
mirror="orbitgate-$C-control-plane"
static() { docker exec "$C-control-plane" curl -sk -H "Authorization: Bearer $1" https://127.0.0.1:9444/api/v1/namespaces; }
for _ in $(seq 60); do
  [ "$(kubectl -n kube-system get pod "$mirror" -o jsonpath='{.metadata.annotations.e2e-run}' 2>/dev/null)" = "$run" ] &&
    static "$alice" | grep -q NamespaceList && break
  sleep 2
done
items() { python3 -c 'import json,sys; print(" ".join(i["metadata"]["name"] for i in json.load(sys.stdin).get("items", [])))'; }
check "static pod: alice sees only dev-a" "$(static "$alice" | items)" "dev-a"
check "static pod: alice watch filtered" "$(docker exec "$C-control-plane" curl -sk -m 3 -H "Authorization: Bearer $alice" 'https://127.0.0.1:9444/api/v1/namespaces?watch=1' |
  python3 -c 'import json,sys; print(" ".join(json.loads(l)["object"]["metadata"]["name"] for l in sys.stdin if l.strip()))')" "dev-a"
check "static pod: admin passthrough" "$(static "$admin" | items | wc -w | tr -d ' ')" "$(kubectl get ns -o name | grep -c .)"
check "static pod: no ServiceAccount token mounted" "$(kubectl -n kube-system get pod "$mirror" -o jsonpath='{.spec.containers[0].volumeMounts[*].name}')" "certs"
sleep 2
check "static pod: lists namespaces as its cert CN" "$(docker exec "$C-control-plane" tail -n +"$((audit0 + 1))" /var/log/kubernetes/audit.log |
  grep '"username":"orbitgate"' | grep -c '"resource":"namespaces"' | awk '{print ($1 > 0)}')" "1"
exit $fail
