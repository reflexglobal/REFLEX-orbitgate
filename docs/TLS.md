# Orbitgate TLS

kubectl talks to Orbitgate over TLS, and bearer tokens travel on that connection. So it must always be TLS, and the cert must never expire unnoticed.

There are two TLS legs:

| leg | who handles it | your job |
|---|---|---|
| kubectl → Orbitgate | Orbitgate's cert in secret `orbitgate-tls` | **this document** |
| Orbitgate → apiserver | the pod's ServiceAccount CA (`ca.crt`), automatic | nothing. After a *cluster* CA rotation, restart the pods: the apiserver CA is read at start. |

## Ground rules

- **SANs:** the cert must list every DNS name and IP users put in their kubeconfig `server:` (node IPs for NodePort, control-plane IPs for DaemonSet + `hostNetwork`, the LB IP/DNS). kubectl ignores the CN.
- **Trust:** users' kubeconfig `certificate-authority-data` must hold the CA that *signed* the cert, not the leaf.
- **Long CA, short leaf:** a long-lived CA (5–10 years) goes into kubeconfigs once, and short-lived leaves (90 days to 1 year) rotate under it. Users never notice a leaf rotation. A *CA* change means redistributing kubeconfigs.
- **Hot reload:** Orbitgate re-reads `tls.crt`/`tls.key` when the secret changes. Kubelet syncs secret volumes within about 1–2 minutes, and **no restart is needed**. This only works because the chart mounts the secret as a directory; never switch to a `subPath` mount (those never update). If a reload fails halfway, Orbitgate keeps serving the last good cert and logs `TLS reload failed`.
- Orbitgate logs `loaded TLS cert "<cn>", expires <date>` at start and on every reload.

## Can I reuse the apiserver's cert?

**No.** That would mean copying the apiserver's private key (`/etc/kubernetes/pki/apiserver.key`) off the control plane into a Secret. Its SANs also don't match Orbitgate's address.

Signing Orbitgate's cert with the **Kubernetes cluster CA** is just as bad. That CA's key also signs client certs, so anyone who can read a Secret holding it can mint themselves `system:masters` (cluster-admin). Keep the cluster CA on the control plane, and use a separate CA for Orbitgate (option A or B).

## Option A (recommended): cert-manager with your own CA

cert-manager issues the cert, renews it before expiry, and writes `orbitgate-tls`. Orbitgate hot-reloads it. In airgapped clusters, mirror the cert-manager images like any other workload; no ACME or internet is involved.

Ideally use an **intermediate CA** signed by your offline root, so the root key never enters the cluster. Users trust the root (or the intermediate).

**A1: an existing CA secret in the cluster** (`caSecretName`). The chart creates an `Issuer` for it. The secret must be in Orbitgate's namespace and hold the CA's `tls.crt` + `tls.key`:

```sh
kubectl -n orbitgate create secret tls airlock-ca --cert=intermediate.crt --key=intermediate.key
helm upgrade --install orbitgate oci://ghcr.io/reflexglobal/charts/orbitgate -n orbitgate --version X.Y.Z \
  --set tls.certManager.enabled=true \
  --set tls.certManager.caSecretName=airlock-ca \
  --set 'tls.certManager.dnsNames={orbitgate.example.internal}' \
  --set 'tls.certManager.ipAddresses={10.0.0.10}'
```

**A2: an existing Issuer or ClusterIssuer** (CA, Vault, step-ca, ...), for when your cluster already has one:

```sh
helm upgrade --install orbitgate ... \
  --set tls.certManager.enabled=true \
  --set tls.certManager.issuerRef.kind=ClusterIssuer \
  --set tls.certManager.issuerRef.name=airlock-ca \
  --set 'tls.certManager.dnsNames={orbitgate.example.internal}'
```

Defaults: `duration: 2160h` (90 days), `renewBefore: 720h` (30 days), ECDSA P-256, new key on every renewal. A failed renewal still leaves you 30 days to notice.

To get the CA for users' kubeconfigs:

```sh
kubectl -n orbitgate get secret orbitgate-tls -o jsonpath='{.data.ca\.crt}'   # already base64: paste as certificate-authority-data
```

## Option B: self-signed (labs, small sites, no cert-manager)

Yes, this works. Make your own small CA and a leaf, not a single self-signed leaf, so leaf renewals don't touch kubeconfigs. With OpenSSL 3+:

```sh
# 1. CA: 10 years. Keep ca.key offline, it is only needed to sign leaves.
openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj "/CN=Airlock Orbitgate CA" \
  -keyout ca.key -out ca.crt

# 2. Leaf: 1 year. List every name/IP users connect to.
openssl req -newkey rsa:3072 -nodes -subj "/CN=orbitgate" -keyout tls.key -out tls.csr
printf 'subjectAltName=DNS:orbitgate.example.internal,IP:10.0.0.10\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > ext
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -extfile ext -out tls.crt

# 3. Install or replace. Running pods pick it up within ~2 minutes, no restart.
kubectl -n orbitgate create secret tls orbitgate-tls --cert=tls.crt --key=tls.key \
  --dry-run=client -o yaml | kubectl apply -f -

# 4. Users: base64 of ca.crt goes into certificate-authority-data.
base64 < ca.crt | tr -d '\n'
```

**Renewal (put it in a calendar, at least a month before `notAfter`):** repeat steps 2 and 3 with the same `ca.key`. Users change nothing.

`test/kind.sh` runs these exact commands, so they're tested.

## Option C: TLS terminated at a load balancer

Set `extraArgs={-plain-http}` and let the LB terminate TLS. Then the LB→pod hop carries bearer tokens **in clear text**; only do this if that network segment is trusted. **TLS passthrough** on the LB with Orbitgate's own cert is better.

## Validity cheat sheet

| what | suggested | notes |
|---|---|---|
| root CA | 10 years, offline | lives in every kubeconfig |
| intermediate CA (cert-manager `caSecretName`) | 2–5 years | rotate before the leaves would outlive it |
| Orbitgate leaf via cert-manager | 90 days, renew at 30 days left | default |
| Orbitgate leaf by hand | 1 year | calendar reminder |

kubectl (Go) doesn't enforce the browsers' 398-day limit; shorter is just safer.

## Monitoring expiry

- **cert-manager:** alert on `certmanager_certificate_expiration_timestamp_seconds - time() < 14*24*3600` and on `certmanager_certificate_ready_status{condition="False"} == 1`.
- **Anywhere:** check what Orbitgate actually serves, which is the source of truth:

  ```sh
  openssl s_client -connect orbitgate.example.internal:30443 </dev/null 2>/dev/null | openssl x509 -noout -enddate -serial
  ```
- **Logs:** `kubectl -n orbitgate logs deploy/orbitgate | grep 'loaded TLS cert'`.

## Runbook: it expired anyway

Symptom: `kubectl` fails with `x509: certificate has expired or is not yet valid`.

1. Confirm: run the `openssl s_client` command above and check `notAfter`.
2. **cert-manager:** run `kubectl -n orbitgate describe certificate orbitgate` and fix what it complains about (issuer not ready, CA secret missing, CA itself expired). To force a reissue, `kubectl -n orbitgate delete secret orbitgate-tls` (or use `cmctl renew`).
3. **Self-signed:** redo steps 2 and 3 of option B.
4. Wait up to 2 minutes for the secret volume to sync. Orbitgate picks the cert up by itself; `kubectl -n orbitgate rollout restart deploy/orbitgate` makes it immediate.
5. If the **CA** expired or changed, every user needs the new `certificate-authority-data`. To make a CA rotation smooth, put old + new CA together in `certificate-authority-data` (concatenated PEM) during the overlap.

Admins aren't locked out meanwhile: direct apiserver access doesn't go through Orbitgate.
