<p align="center"><img src="docs/logo.png" width="220" alt="Orbitgate"></p>

# Orbitgate

[![Release](https://img.shields.io/github/v/release/reflexglobal/REFLEX-orbitgate?include_prereleases&sort=semver&label=version)](https://github.com/reflexglobal/REFLEX-orbitgate/releases)
[![Chart](https://img.shields.io/badge/dynamic/yaml?url=https%3A%2F%2Fraw.githubusercontent.com%2Freflexglobal%2FREFLEX-orbitgate%2Fmain%2Fcharts%2Forbitgate%2FChart.yaml&query=%24.version&label=helm%20chart&prefix=v)](charts/orbitgate)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/orbitgate)](https://artifacthub.io/packages/search?repo=orbitgate)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Part of **Airlock**, Reflex's toolkit for airgapped Kubernetes deployments and defense clusters.

Orbitgate is a small pass-through proxy in front of the kube-apiserver. It does one thing: **`kubectl get ns` only shows the namespaces you have access to.** Cluster admins see everything, and dev teams don't see each other's namespaces.

Everything else is the apiserver's job, unchanged:

- Authentication, RBAC, admission and audit all run on the apiserver. Orbitgate forwards the user's credentials untouched.
- Orbitgate never sees a decision it could get wrong, and it holds no rights beyond `list namespaces`.
- It runs next to the real apiserver: as normal pods (NodePort or LoadBalancer), or as a DaemonSet on the control-plane nodes, optionally listening directly on their IPs. The apiserver itself is unchanged, and admins can keep using it directly.

```
kubectl --(user's own token)--> orbitgate --(same token, untouched)--> kube-apiserver
```

## Why Orbitgate

**The gap in Kubernetes.** RBAC decides *whether* you may list a resource, not *which items* you get back. For namespaces that leaves two bad options:

- **Grant cluster-wide `list namespaces`:** every tenant sees every other tenant's namespace names. Those names tend to leak customer names, project codenames and environments, which is a real problem in shared, regulated or defense clusters.
- **Don't grant it:** `kubectl get ns` is Forbidden. Developers can't discover their own namespaces, and tools that start from a namespace list (dashboards, IDE plugins, k9s) break or have to be fed names by hand.

**What exists already is heavy.** OpenShift projects, Rancher projects, Capsule + capsule-proxy and vcluster all solve this, but they bring a platform, CRDs or a tenancy model along. Older auth proxies like kube-oidc-proxy (archived) authenticate but don't filter.

**What Orbitgate gives you:**

| | |
|---|---|
| **Tenant separation** | Teams only see their own namespaces; cluster admins see everything. |
| **Nothing to migrate** | Works with your existing RoleBindings. No CRDs, no tenant objects, no apiserver flags or restarts. |
| **Apiserver stays the authority** | Credentials pass through untouched, so authn, RBAC, admission and audit behave exactly as on direct access. Audit logs show the real user. |
| **Tiny attack surface** | One static binary, no dependencies beyond the Go standard library, a `FROM scratch` image of ~9 MB, only `list namespaces` RBAC, no impersonation rights. Fails closed. |
| **Airgap-friendly** | No external calls; mirror one image and one chart. TLS from your own CA, with hot reload so renewals never need a restart. |
| **Fits your topology** | Normal pods behind a NodePort/LoadBalancer, or a DaemonSet on the control planes right next to the apiserver. Admins can always bypass it. |
| **Any identity provider** | Whatever the apiserver accepts (OIDC via Keycloak, Dex, Okta, Entra; ServiceAccount tokens; webhook auth). |

## How the namespace list works

For `GET /api/v1/namespaces` (a list, not a watch):

1. Orbitgate forwards it as the user. If the apiserver allows it (e.g. cluster-admin), the real answer passes through unchanged.
2. If the apiserver says **403**, Orbitgate lists namespaces with its own ServiceAccount. It then asks the apiserver *as the user* (a `SelfSubjectAccessReview`) whether the user can `list pods` in each namespace.
3. Only namespaces where the answer is yes are returned. If a check errors, that namespace is hidden (fail closed). `remainingItemCount` is removed so the total count doesn't leak.

Every other request (Deployments, StatefulSets, CRDs, Helm, logs, exec, port-forward, and namespace watches) is proxied unchanged, and RBAC decides.

"Tenant of a namespace" means "can list pods there", which `view`, `edit` and `admin` all grant. A custom role without pods won't show up in `get ns`, though it still works with `-n <ns>`.

## Audit logging

Because credentials are passed through, audit events look exactly like direct apiserver use:

| what | audit event |
|---|---|
| any request via Orbitgate | `user.username` = the real user, no `impersonatedUser`; `sourceIPs` = [client IP, Orbitgate pod IP] |
| `get ns` by a cluster-admin | one normal `list namespaces` by that user |
| `get ns` by a tenant | a `list namespaces` by the user (403), a `list namespaces` by `system:serviceaccount:<ns>:orbitgate`, and one `create selfsubjectaccessreviews` by the user per namespace |

The client IP comes from `X-Forwarded-For`, which Orbitgate sets itself (any client-sent value is replaced).

## Requirements

**Cluster:** any Kubernetes with RBAC. Also needed:
- the image in a registry the cluster can pull from;
- a TLS cert for Orbitgate (see [docs/TLS.md](docs/TLS.md));
- a NodePort or LoadBalancer.

**Authentication:** users must authenticate with **bearer tokens** the apiserver accepts:
- OIDC via the apiserver's `--oidc-*` flags or `AuthenticationConfiguration`, with [kubelogin](https://github.com/int128/kubelogin) on the client side;
- ServiceAccount tokens;
- webhook token auth.

Orbitgate itself knows nothing about OIDC, so any provider the apiserver supports works (Keycloak, Dex, Okta, Entra, ...). **Client-certificate users can't go through a TLS-terminating proxy**; they keep using the apiserver directly, which is usually only break-glass admins.

**Client certificates don't work through Orbitgate.** Orbitgate terminates TLS, so a client certificate never reaches the apiserver, and the request arrives without credentials. kubectl then reports `error: You must be logged in to the server (Unauthorized)` (or `Forbidden ... system:anonymous` if anonymous auth is on). Certificate users, usually break-glass admins such as the kubeadm `admin.conf`, keep a context that points straight at the apiserver:

```sh
kubectl config set-context breakglass --cluster=<apiserver-cluster> --user=<cert-user>   # server: https://<apiserver>:6443
kubectl --context=breakglass get ns
```

**Tenants:** a namespace plus a RoleBinding granting `view`, `edit` or `admin` (or any role with `list pods`).

**Build:** Go 1.26 or Docker. **Test env:** Docker, kind, kubectl, helm, openssl, python3, and internet access to pull images.

## Install

```sh
helm install orbitgate oci://ghcr.io/reflexglobal/charts/orbitgate --version <X.Y.Z> \
  -n orbitgate --create-namespace \
  --set image.repository=<your-registry>/reflex/orbitgate \
  --set tls.certManager.enabled=true --set tls.certManager.caSecretName=<your-ca-secret> \
  --set 'tls.certManager.dnsNames={orbitgate.example.internal}'
```

Airgapped: `helm pull oci://ghcr.io/reflexglobal/charts/orbitgate --version X.Y.Z` (or take the `.tgz` from the GitHub release), and mirror `ghcr.io/reflexglobal/orbitgate:X.Y.Z` into the enclave registry.

| value | default | |
|---|---|---|
| `image.repository` / `image.tag` | `ghcr.io/reflexglobal/orbitgate` / appVersion | |
| `kind` | `Deployment` | `Deployment`: normal pods behind the Service. `DaemonSet`: one pod on every control-plane node |
| `replicas` | 2 | Deployment only |
| `hostNetwork` | false | DaemonSet only: listen directly on each control-plane node IP at `listenPort` |
| `listenPort` | 8443 | container port, or node port with `hostNetwork` (must be free on the nodes) |
| `daemonSet.affinity` / `.tolerations` | control-plane nodes (kubeadm, RKE2, k3s) | DaemonSet scheduling |
| `nodeSelector` / `affinity` / `tolerations` | | Deployment scheduling (`nodeSelector` applies to both) |
| `service.type` / `service.nodePort` | `NodePort` / 30443 | or `LoadBalancer`; `ClusterIP` is enough with `hostNetwork` |
| `tls.secretName` | `orbitgate-tls` | bring your own, or let cert-manager create it |
| `tls.certManager.enabled` | false | see [docs/TLS.md](docs/TLS.md) |
| `tls.certManager.caSecretName` | | existing CA secret in the release namespace; the chart makes an Issuer |
| `tls.certManager.issuerRef` | ClusterIssuer `airlock-ca` | existing (Cluster)Issuer, used when `caSecretName` is empty |
| `tls.certManager.dnsNames` / `ipAddresses` | | every name/IP users connect to |
| `extraArgs` | `[]` | e.g. `-plain-http` behind a TLS-terminating LB |

## User kubeconfig

Same user entry as for the apiserver; only the cluster's `server` and CA change:

```yaml
clusters:
  - name: airlock
    cluster:
      server: https://orbitgate.example.internal:30443
      certificate-authority-data: <base64 of the CA that signed Orbitgate's cert>
users:
  - name: oidc
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1beta1
        command: kubectl
        args: [oidc-login, get-token, --oidc-issuer-url=<issuer>, --oidc-client-id=<client>]
```

## Releases and versioning

Push a tag `vX.Y.Z` and CI tests, then publishes:
- the image `ghcr.io/reflexglobal/orbitgate:X.Y.Z` (amd64 + arm64);
- the chart `oci://ghcr.io/reflexglobal/charts/orbitgate` version `X.Y.Z` (chart version = app version);
- a GitHub release with the chart `.tgz`.

Each release also signs the image and chart with cosign (keyless) and publishes ArtifactHub metadata.

**Commits** follow [Conventional Commits](https://www.conventionalcommits.org) (`type(scope)!: subject`), and CI rejects anything else. The ArtifactHub changelog is generated from them at release time:

| commit | changelog |
|---|---|
| `feat: ...` | added |
| `fix: ...` | fixed |
| `fix(security): ...` | security |
| `perf: ...` / `refactor: ...` | changed |
| `type!: ...` | marked BREAKING |
| `docs`, `chore`, `ci`, `test`, `build`, `style` | not listed |

**Release:** `git tag vX.Y.Z && git push --tags` (pre-releases: `vX.Y.Z-alpha`, `-beta.1`, `-rc.1`; marked as pre-release on GitHub and ArtifactHub). Pick the version per [semver](https://semver.org): a `!` means a major bump (minor while on 0.x), `feat` a minor bump, `fix` a patch.

ArtifactHub (repo `orbitgate`, `oci://ghcr.io/reflexglobal/charts/orbitgate`) can only read the chart while the GHCR packages are **public**. The icon (`docs/icon.png`) shows once the GitHub repo is public too.

## Develop

```sh
go test ./...
./test/kind.sh   # own kind cluster "orbitgate" with audit logging; uses test/.kubeconfig, never ~/.kube/config
```

The e2e checks tenant isolation, admin passthrough, logs and exec through the proxy, audit identity, and cert rotation from an in-cluster CA without restarts.

## Community

- [Contributing](CONTRIBUTING.md): dev setup, Conventional Commits, PR checklist
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security policy](SECURITY.md): report vulnerabilities privately
- [Maintainers](MAINTAINERS.md)

## License

Copyright © 2026 REFLEX GLOBAL B.V. Orbitgate is free and open source software under the [MIT License](LICENSE).
