#!/usr/bin/env bash
# Copyright (c) 2026 REFLEX GLOBAL B.V.
# SPDX-License-Identifier: MIT
# Own kind cluster "orbitgate" (audit logging on) + Orbitgate via the Helm chart, then e2e through the proxy.
# Users are ServiceAccount tokens: Orbitgate passes any credential the apiserver accepts (OIDC works the same).
# Re-runnable. Teardown: kind delete cluster --name orbitgate --kubeconfig test/.kubeconfig
set -euo pipefail
cd "$(dirname "$0")/.."
C=orbitgate
export KUBECONFIG=$PWD/test/.kubeconfig  # own kubeconfig: never touches ~/.kube/config or its current context
tmp=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$tmp"' EXIT

kind get clusters | grep -qx "$C" || kind create cluster --name "$C" --kubeconfig "$KUBECONFIG" --config test/kind-config.yaml
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
  --set image.repository=orbitgate --set image.tag=dev --set tls.certManager.enabled=false >/dev/null  # first: drops a cert-manager Certificate left by a previous run
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
check "alice sees only dev-a" "$(nss "$alice")" "namespace/dev-a"
check "bob sees only dev-b" "$(nss "$bob")" "namespace/dev-b"
check "admin sees all (passthrough)" "$(og "$admin" get ns -o name | grep -c .)" "$(kubectl get ns -o name | grep -c .)"
check "alice json list" "$(og "$alice" get ns -o jsonpath='{.items[*].metadata.name}')" "dev-a"
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
kubectl -n orbitgate create secret tls airlock-ca --cert="$tmp/ca.crt" --key="$tmp/ca.key" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
until helm upgrade orbitgate charts/orbitgate -n orbitgate --reuse-values \
  --set tls.certManager.enabled=true --set tls.certManager.caSecretName=airlock-ca \
  --set 'tls.certManager.dnsNames={localhost}' --set 'tls.certManager.ipAddresses={127.0.0.1}' >/dev/null 2>&1; do sleep 3; done  # webhook warm-up
kubectl -n orbitgate wait --for=condition=Ready certificate/orbitgate --timeout=120s >/dev/null
for _ in $(seq 60); do [ "$(served)" != "$before" ] && break; sleep 3; done  # kubelet syncs secret volumes every ~60s
check "rotated cert served without restart" "$([ "$(served)" != "$before" ] && echo yes)" "yes"
check "pods not restarted" "$(kubectl -n orbitgate get pods -o name | sort)" "$pods"
check "kubectl still trusts it" "$(og "$alice" get ns -o name)" "namespace/dev-a"
exit $fail
