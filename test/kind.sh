#!/usr/bin/env bash
# Own kind cluster "orbitgate" + Dex + Orbitgate, then e2e through the proxy. Re-runnable.
# Teardown: kind delete cluster --name orbitgate --kubeconfig test/.kubeconfig
set -euo pipefail
cd "$(dirname "$0")/.."
C=orbitgate
export KUBECONFIG=$PWD/test/.kubeconfig  # own kubeconfig: never touches ~/.kube/config or its current context
tmp=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$tmp"' EXIT

kind get clusters | grep -qx "$C" || kind create cluster --name "$C" --kubeconfig "$KUBECONFIG"
docker build -q -t orbitgate:dev . >/dev/null
kind load docker-image orbitgate:dev --name "$C"

kubectl apply -f test/dex.yaml >/dev/null
kubectl -n dex rollout status deploy/dex --timeout=120s

openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=orbitgate \
  -keyout "$tmp/tls.key" -out "$tmp/tls.crt" 2>/dev/null
sed -e 's#image: .*#image: orbitgate:dev#' \
    -e 's#-issuer=.*#-issuer=http://dex.dex.svc:5556/dex#' deploy/orbitgate.yaml | kubectl apply -f - >/dev/null
kubectl -n orbitgate create secret tls orbitgate-tls --cert="$tmp/tls.crt" --key="$tmp/tls.key" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n orbitgate rollout restart deploy/orbitgate >/dev/null
kubectl -n orbitgate rollout status deploy/orbitgate --timeout=120s

for ns in dev-a dev-b; do kubectl create ns "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null; done
kubectl -n dev-a create rolebinding alice --clusterrole=edit --user=oidc:alice@airlock.test --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n dev-b create rolebinding bob --clusterrole=edit --user=oidc:bob@airlock.test --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create clusterrolebinding orbitgate-test-admin --clusterrole=cluster-admin --user=oidc:admin@airlock.test --dry-run=client -o yaml | kubectl apply -f - >/dev/null
sleep 3  # RBAC informer lag

kubectl -n dex port-forward svc/dex 15556:5556 >/dev/null &
kubectl -n orbitgate port-forward svc/orbitgate 18443:443 >/dev/null &
sleep 2

token() {
  curl -fsS -u orbitgate:test-secret http://localhost:15556/dex/token \
    -d grant_type=password -d scope="openid email" -d username="$1@airlock.test" -d password=password |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["id_token"])'
}
og() { local t=$1; shift; KUBECONFIG=/dev/null kubectl --server=https://localhost:18443 --insecure-skip-tls-verify --token="$t" "$@"; }
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2' want '$3'"; fail=1; fi; }
nss() { og "$1" get ns -o name | tr '\n' ' ' | sed 's/ $//'; }

admin=$(token admin); alice=$(token alice); bob=$(token bob)
check "alice sees only dev-a" "$(nss "$alice")" "namespace/dev-a"
check "bob sees only dev-b" "$(nss "$bob")" "namespace/dev-b"
check "admin sees all" "$(og "$admin" get ns -o name | grep -c .)" "$(kubectl get ns -o name | grep -c .)"
check "alice json list" "$(og "$alice" get ns -o jsonpath='{.items[*].metadata.name}')" "dev-a"
check "alice can create in dev-a" "$(og "$alice" -n dev-a create configmap e2e --dry-run=server -o name 2>&1)" "configmap/e2e"
check "alice denied dev-b" "$(og "$alice" -n dev-b get pods 2>&1 | grep -c Forbidden)" "1"
check "alice --as admin ignored" "$(og "$alice" --as=oidc:admin@airlock.test -n dev-b get pods 2>&1 | grep -c Forbidden)" "1"
check "bad token rejected" "$(og garbage get ns 2>&1 | grep -c "provide credentials")" "1"
exit $fail
