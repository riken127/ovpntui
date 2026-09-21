# Contributing to ovpntui

Bug reports, usability improvements, and OpenVPN compatibility fixes are welcome.

## Set up your environment

- Go 1.24 or newer and `make` are needed to build the project.
- OpenVPN 2.x is needed only for manual VPN testing. The build and existing tests do not require administrator privileges or change system routes.
- `golangci-lint` is needed only for `make lint`.

```sh
git clone https://github.com/riken127/ovpntui.git
cd ovpntui
make check
./bin/ovpntui --version
```

`make check` checks formatting, runs `go vet` and the existing tests, and builds both binaries. `make race` runs the tests with Go's race detector. `make fmt` formats Go files. To try a local build, `make install` installs both binaries in `~/.local/bin`.

## Project structure

- `cmd/ovpntui`: CLI and TUI startup.
- `cmd/ovpntuid`: per-user daemon.
- `internal/tui`: terminal interface.
- `internal/daemon`: local protocol, daemon startup, and lifecycle.
- `internal/openvpn`: OpenVPN process, management socket, and session state.
- `internal/profile`: profile import, validation, and storage.
- `internal/credentials`: optional Secret Service integration.

The daemon runs as a normal user and elevates only the OpenVPN process. Imported-profile validation and private-directory permissions are security boundaries. Explain changes to either in your pull request.

## Issues and pull requests

1. Search existing issues and pull requests before opening a new one.
2. Describe the observed and expected behavior, reproduction steps, operating system, Go version, and OpenVPN version.
3. Keep the change focused. Explain what changed and how you verified it.
4. Run `make check` before submitting. For supervisor or protocol changes, also run `make race`.

Integration tests use a simulated OpenVPN process. For routing or disconnect changes, describe any manual validation on a test VPN and the routes observed before and after. The tests do not create a real tunnel.

Do not publish real profiles, private keys, passwords, SSO URLs containing tokens, or sensitive logs in an issue or pull request. Redact these values from examples.
