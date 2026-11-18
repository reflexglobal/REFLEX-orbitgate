# Orbitgate as a static pod (Talos)

Static pods are started by the kubelet from a manifest on the node. They can't use ServiceAccounts, Secrets or ConfigMaps, and admission webhooks never mutate them. That makes them a good fit for something that sits next to the apiserver on every control plane and should keep working when the cluster's own workloads don't.

Without a ServiceAccount, Orbitgate needs another identity for its one own call: listing namespaces for tenants. Give it a **client certificate**:

```
-apiserver=https://127.0.0.1:7445        # or https://127.0.0.1:6443 for the local apiserver only
-apiserver-ca=/certs/apiserver-ca.crt    # the Kubernetes CA (verifies the apiserver)
-client-cert=/certs/client.crt           # Orbitgate's own identity, reloaded on change
-client-key=/certs/client.key
-tls-cert=/certs/tls.crt                 # what kubectl sees, as in docs/TLS.md
-tls-key=/certs/tls.key
```

When `-client-cert` is set, the ServiceAccount token is not read. The client cert is only presented on Orbitgate's own connections; user requests go over a separate connection pool that carries nothing but the user's token. Orbitgate re-reads the cert when the file changes and recycles idle connections every minute, so a renewed cert is in use within a minute or two, without a restart.

## What the identity needs (RBAC)

`list` and `watch` on `namespaces`, nothing else (`watch` serves tenants' filtered `kubectl get ns -w`).

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: orbitgate-static}
rules:
  - {apiGroups: [""], resources: [namespaces], verbs: [list, watch]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: orbitgate-static}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: orbitgate-static}
subjects:
  - {apiGroup: rbac.authorization.k8s.io, kind: User, name: orbitgate}  # the cert's CN
```

No `selfsubjectaccessreviews`, no `impersonate`. The per-namespace checks are `SelfSubjectAccessReview`s sent **with the user's own token**, not with Orbitgate's identity and not via impersonation. The apiserver answers them for the user, who may create them through the default `system:basic-user` role. Every other request also runs with the user's token, so the cert can't be used to do more than list and watch namespaces.

## Minting the client cert

Subject: **`CN=orbitgate`, no `O`**. The CN becomes the username in RBAC and audit logs. Every `O` becomes a group, so leave it out: `O=system:masters` would make it cluster-admin, and `O=system:nodes` would hand it node rights. Don't use a `system:` prefix for the CN either; those names are reserved.

### Option A (recommended): the Kubernetes CSR API

The CA key never leaves the control plane. Needs an admin kubeconfig (`talosctl -n <cp> kubeconfig`) and the controller-manager signing client certs, which it does by default.

```sh
openssl req -newkey rsa:3072 -nodes -subj /CN=orbitgate -keyout client.key -out client.csr
kubectl apply -f - <<EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata: {name: orbitgate}
spec:
  request: $(base64 < client.csr | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 31536000   # 1 year; capped by the controller-manager's --cluster-signing-duration
  usages: [client auth]
EOF
kubectl certificate approve orbitgate
kubectl get csr orbitgate -o jsonpath='{.status.certificate}' | base64 -d > client.crt
kubectl delete csr orbitgate   # CSR objects are garbage-collected anyway; delete before the next renewal
openssl x509 -in client.crt -noout -subject -enddate
```

If the CSR stays `Approved` but never gets a certificate, the controller-manager has no signing key configured; use option B.

### Option B: sign with the Kubernetes CA key directly

On Talos the CA is in the secrets bundle (`talosctl gen secrets` output, `certs.k8s.crt` / `certs.k8s.key`, base64). Do this on a trusted workstation and don't keep the key around: anyone holding it can mint cluster-admin.

```sh
yq -r .certs.k8s.crt secrets.yaml | base64 -d > k8s-ca.crt
yq -r .certs.k8s.key secrets.yaml | base64 -d > k8s-ca.key
openssl req -newkey rsa:3072 -nodes -subj /CN=orbitgate -keyout client.key -out client.csr
printf 'extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n' > ext
openssl x509 -req -in client.csr -CA k8s-ca.crt -CAkey k8s-ca.key -CAcreateserial -days 365 -extfile ext -out client.crt
shred -u k8s-ca.key 2>/dev/null || rm -P k8s-ca.key
```

### The other files

- `apiserver-ca.crt`: the Kubernetes CA cert, e.g. `kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d` on the admin kubeconfig. Not the key.
- `tls.crt` / `tls.key`: Orbitgate's serving cert from **your own CA**, never the Kubernetes CA (see [TLS.md](TLS.md)). SANs: every control-plane IP, the shared VIP if you use one, and any DNS name users put in their kubeconfig.

## Talos machine config patch

Apply to the control-plane nodes only. Paste the PEM files as literal blocks. The cert files are identical on every control plane; per-node client certs (`CN=orbitgate`, but signed separately) also work.

```yaml
# orbitgate.patch.yaml
machine:
  files:
    - {path: /var/lib/orbitgate/apiserver-ca.crt, op: create, permissions: 0o444, content: |
        -----BEGIN CERTIFICATE-----
        ...
        -----END CERTIFICATE-----
      }
    - {path: /var/lib/orbitgate/client.crt, op: create, permissions: 0o444, content: |
        ...
      }
    - {path: /var/lib/orbitgate/client.key, op: create, permissions: 0o400, content: |
        ...
      }
    - {path: /var/lib/orbitgate/tls.crt, op: create, permissions: 0o444, content: |
        ...
      }
    - {path: /var/lib/orbitgate/tls.key, op: create, permissions: 0o400, content: |
        ...
      }
  pods:
    - apiVersion: v1
      kind: Pod
      metadata: {name: orbitgate, namespace: kube-system}
      spec:
        hostNetwork: true
        priorityClassName: system-node-critical
        containers:
          - name: orbitgate
            image: ghcr.io/reflexglobal/orbitgate:X.Y.Z   # your registry mirror in an airgap
            args:
              - -listen=:8443
              - -apiserver=https://127.0.0.1:7445        # KubePrism: any healthy apiserver
              - -apiserver-ca=/certs/apiserver-ca.crt
              - -client-cert=/certs/client.crt
              - -client-key=/certs/client.key
              - -tls-cert=/certs/tls.crt
              - -tls-key=/certs/tls.key
              - -metrics-listen=:9091                    # /metrics, /healthz, /readyz (plain HTTP)
            livenessProbe: {httpGet: {path: /healthz, port: 9091}}
            # The files are root-owned (Talos sets no owner), so run as uid 0 with no capabilities at all.
            securityContext: {runAsUser: 0, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
            resources: {requests: {cpu: 10m, memory: 32Mi}, limits: {memory: 128Mi}}
            volumeMounts: [{name: certs, mountPath: /certs, readOnly: true}]
        volumes: [{name: certs, hostPath: {path: /var/lib/orbitgate, type: Directory}}]
```

```sh
talosctl -n <cp1>,<cp2>,<cp3> patch machineconfig --patch @orbitgate.patch.yaml --dry-run   # shows the diff and whether it needs a reboot
talosctl -n <cp1>,<cp2>,<cp3> patch machineconfig --patch @orbitgate.patch.yaml
kubectl -n kube-system get pods -o wide | grep orbitgate   # mirror pods: orbitgate-<node>
```

Notes:

- **Ports:** with `hostNetwork` Orbitgate listens on the node itself (8443 for users, 9091 for metrics), so both must be free next to the apiserver (6443), KubePrism (7445), apid/trustd (50000/50001), etcd (2379/2380), the kubelet (10250) and your CNI. They normally are; check with `talosctl -n <cp> netstat -l`.
- **Apiserver address:** `127.0.0.1:7445` is KubePrism (on by default since Talos 1.6), so Orbitgate keeps working while the local apiserver restarts. Use `https://127.0.0.1:6443` to only ever talk to the local one. Either way the apiserver cert must list `127.0.0.1` (Talos includes it; otherwise add it under `cluster.apiServer.certSANs`).
- **`machine.files`:** `op: create` only works under `/var`, and Talos refuses it for a file that already exists; `/var` survives reboots. Check `talosctl -n <cp> dmesg | grep -i file` after applying and after the first reboot, and switch the entries to `op: overwrite` if your Talos version complains on later boots. This part has not been exercised on a live Talos cluster yet (the e2e in `test/kind.sh` runs the same static pod on kind).
- **Renewal:** mint a new client cert (and serving cert) before `notAfter` and write it with `op: overwrite`. Orbitgate picks up both, and a rotated `apiserver-ca.crt`, without a restart once the files change on disk. With `-metrics-listen`, alert on `orbitgate_client_cert_expiry_timestamp_seconds` and `orbitgate_tls_cert_expiry_timestamp_seconds`.
- **Image:** the kubelet pulls it like any pod image, so mirror it into the registry the nodes use (`machine.registries` mirrors apply).

## Users

Users point their kubeconfig at the control planes on the Orbitgate port, `server: https://<cp-ip-or-vip>:8443`, with the CA that signed `tls.crt`. Talos' shared VIP (`machine.network.interfaces[].vip`) works here too: it is an address on one control plane at a time, and every control plane runs Orbitgate. Bearer tokens only (OIDC, ServiceAccount tokens); see the [README](../README.md#requirements).

## Closing 6443 to everyone but admins

With Orbitgate on every control plane, user networks no longer need the apiserver port. Talos' ingress firewall can restrict 6443 to the nodes, the pods and an admin network, and open 8443 to users. The rules only take effect with `ingress: block` as the default, which in turn needs allow rules for everything else the nodes use (apid, trustd, etcd, kubelet, CNI). Start from the recommended rule set in the Talos "Ingress firewall" docs and add:

```yaml
apiVersion: v1alpha1
kind: NetworkDefaultActionConfig
ingress: block
---
apiVersion: v1alpha1
kind: NetworkRuleConfig
name: kube-apiserver
portSelector: {ports: [6443], protocol: tcp}
ingress:
  - subnet: 10.0.10.0/24    # all node IPs: kubelets, KubePrism and the controllers talk to 6443
  - subnet: 10.244.0.0/16   # pod CIDR: in-cluster clients via kubernetes.default.svc
  - subnet: 10.0.99.0/24    # admin / jump-host network
---
apiVersion: v1alpha1
kind: NetworkRuleConfig
name: orbitgate
portSelector: {ports: [8443], protocol: tcp}
ingress:
  - subnet: 10.0.0.0/8      # user networks
```

What this does and doesn't do:

- It shrinks who can reach the apiserver directly. It is **not** what keeps tenants apart: authorization is still the apiserver's RBAC on every request, through Orbitgate or not. A tenant reaching 6443 from inside a pod just gets the same 403 on `list namespaces`.
- Workloads and nodes are unaffected: they reach the apiserver from the node and pod ranges. Loopback (KubePrism, Orbitgate's own upstream) isn't filtered.
- Client-certificate users (break-glass admins) can't go through Orbitgate, which terminates TLS. They use 6443 from the admin network.

**Break-glass.** Talos' own API (port 50000, mutual TLS with your `talosconfig`) is independent of Kubernetes and of these rules as long as it stays reachable from the admin network. From there you can always:

- get a fresh admin kubeconfig: `talosctl -n <cp> kubeconfig`;
- reopen 6443 to where you are: `talosctl -n <cp> patch machineconfig --patch @open-6443.yaml` with your address added to the `kube-apiserver` rule (network rules apply without a reboot; check with `--dry-run`);
- read logs without the apiserver: `talosctl -n <cp> logs kubelet`, `talosctl -n <cp> containers -k`.

Keep `talosconfig` where break-glass credentials live (a vault, offline copy), because it is now the key that reopens the door.
