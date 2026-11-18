# Security Policy

Orbitgate sits in front of the Kubernetes API and handles user credentials, so we take reports seriously.

## Reporting a vulnerability

**Do not open a public issue.** Report it privately through GitHub: **Security → Report a vulnerability** on this repository ([private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)).

Please include the version, how Orbitgate is deployed, and steps to reproduce.

- We acknowledge within **3 working days** and aim to ship a fix for confirmed issues within **30 days**.
- We coordinate disclosure with you and credit you in the advisory, unless you prefer otherwise.

## Supported versions

Only the latest release gets security fixes while Orbitgate is pre-1.0.

## Scope

Especially interesting:
- a tenant learning namespace names they have no access to;
- Orbitgate's ServiceAccount rights being usable by a caller;
- credentials leaking (logs, other users, upstream).

Out of scope: misconfigured RBAC in your cluster, and issues in the kube-apiserver itself (report those to [Kubernetes](https://kubernetes.io/docs/reference/issues-security/security/)).

## Verifying releases

Images and charts are signed with cosign (keyless, GitHub Actions OIDC):

```sh
cosign verify ghcr.io/reflexglobal/orbitgate:<version> \
  --certificate-identity-regexp '^https://github.com/reflexglobal/REFLEX-orbitgate/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
