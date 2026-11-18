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
- Orbitgate's own credentials (ServiceAccount token or client cert) being usable by a caller;
- credentials leaking (logs, other users, upstream).

Out of scope: misconfigured RBAC in your cluster, and issues in the kube-apiserver itself (report those to [Kubernetes](https://kubernetes.io/docs/reference/issues-security/security/)).

## Scanning and patching

- CI runs `govulncheck` and Trivy (image CVEs and Dockerfile/Helm misconfigurations) on every change and weekly. Fixable HIGH/CRITICAL findings fail the build and block releases.
- The image is `FROM scratch` (only the static binary), so there is no OS layer to patch. The Go toolchain is pinned to an exact patch version, which Dependabot bumps daily.
- Known, intentional finding: `hostNetwork: true` (DaemonSet mode, opt-in) triggers KSV-0009 "access to host network".

## Verifying releases

Images and charts are signed with cosign (keyless, GitHub Actions OIDC):

```sh
cosign verify ghcr.io/reflexglobal/orbitgate:<version> \
  --certificate-identity-regexp '^https://github.com/reflexglobal/orbitgate/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
