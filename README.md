# Orbitgate

Part of **Airlock**, Reflex's toolkit for airgapped Kubernetes deployments.

Orbitgate is a small kube-apiserver proxy for tenant separation:

- Authenticates `kubectl` users with OIDC (Dex, Keycloak, Okta, Entra ID, or any other standards-compliant issuer).
- Forwards every request to the real apiserver **as that user** (impersonation), so normal RBAC applies.
- `kubectl get ns` only returns namespaces the user is a tenant of: namespaces where they can `list pods`. A cluster admin sees everything.

It runs next to the real apiserver as a Deployment exposed with a NodePort or LoadBalancer. The apiserver itself is unchanged, and admins can keep using it directly.

```
kubectl --(OIDC id_token)--> orbitgate --(SA token + Impersonate-User/Group)--> kube-apiserver
```

## Deploy

1. Mirror the image into your airgapped registry: `docker build -t <registry>/reflex/orbitgate:<tag> .`
2. Create the TLS secret: `kubectl -n orbitgate create secret tls orbitgate-tls --cert=tls.crt --key=tls.key`
3. Edit `image`, `-issuer` and `-client-id` in `deploy/orbitgate.yaml`, then `kubectl apply -f deploy/orbitgate.yaml`.
4. Give tenants a RoleBinding in their namespace. Users and groups are prefixed with `oidc:`:

   ```sh
   kubectl -n team-a create rolebinding team-a --clusterrole=edit --group=oidc:team-a
   ```

The OIDC issuer must be reachable from inside the cluster. In an airgapped enclave that means an in-enclave Keycloak or Dex.

## Flags

| flag | default | |
|---|---|---|
| `-issuer` | | OIDC issuer URL (required) |
| `-client-id` | | expected token audience (required) |
| `-username-claim` | `email` | e.g. `preferred_username` for Entra/Keycloak |
| `-groups-claim` | `groups` | |
| `-prefix` | `oidc:` | prepended to usernames and groups |
| `-tls-cert` / `-tls-key` | | required unless `-plain-http` |
| `-plain-http` | false | only behind a TLS-terminating LB |
| `-apiserver` | `https://kubernetes.default.svc` | |

## kubeconfig for users

Use [kubelogin](https://github.com/int128/kubelogin) to fetch the token:

```yaml
users:
  - name: orbitgate
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1beta1
        command: kubectl
        args: [oidc-login, get-token, --oidc-issuer-url=<issuer>, --oidc-client-id=orbitgate]
clusters:
  - name: orbitgate
    cluster: {server: "https://<node-or-lb>:30443", certificate-authority: orbitgate-ca.crt}
```

## Security notes

- The Orbitgate ServiceAccount can impersonate any user or group. Orbitgate strips every caller-supplied `Authorization` and `Impersonate-*` header, and it refuses identities that start with `system:`, so a token claiming `system:masters` is rejected.
- The namespace list is fetched with the proxy's own SA, and each namespace is then checked with a SubjectAccessReview on behalf of the user. If a check errors, that namespace is hidden (fail closed). `remainingItemCount` is removed so the total namespace count doesn't leak.
- Only plain list calls to `/api/v1/namespaces` are filtered. A watch on namespaces goes through as the user, so a dev gets Forbidden.

## Develop

```sh
go test ./...
./test/kind.sh   # own kind cluster "orbitgate" + Dex + e2e; uses test/.kubeconfig, not ~/.kube/config
```
