# Contributing to Orbitgate

Thanks for helping! Orbitgate is deliberately small: one Go file, no dependencies. Contributions that keep it that way are the easiest to merge.

## Before you start

- **Bugs:** open an issue with steps to reproduce (bug template).
- **Features:** open an issue first so we can agree on scope before you write code. Orbitgate only filters namespace lists; authentication, RBAC and admission stay with the kube-apiserver.
- **Security issues:** never in a public issue. See [SECURITY.md](SECURITY.md).

## Development

Requirements: Go 1.26, Docker, kind, kubectl, helm, openssl, python3.

```sh
go vet ./... && go test ./...   # unit tests
helm lint charts/orbitgate      # chart
./test/kind.sh                  # e2e on a throwaway kind cluster (own kubeconfig, never touches ~/.kube/config)
```

CI runs all three on every PR.

## Pull requests

- One logical change per PR, with a test when you change behaviour (a unit test in `main_test.go` or a check in `test/kind.sh`).
- No new Go dependencies unless there is no reasonable alternative; explain it in the PR.
- Update `README.md` / `docs/` and `values.schema.json` when you change flags or chart values.

### Commit messages

[Conventional Commits](https://www.conventionalcommits.org) are required and checked by CI. They also generate the changelog.

```
feat(chart): add podAnnotations
fix: keep serving the last good cert when reload fails
fix(security)!: reject ... (! = breaking change)
docs: explain DaemonSet mode
```

Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore`, `style`, `revert`.

### Sign-off

Sign your commits (`git commit -s`) to certify the [Developer Certificate of Origin](https://developercertificate.org): you wrote the change or have the right to submit it under the MIT license.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
