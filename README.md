# ovpntui

ovpntui is a terminal interface for managing OpenVPN profiles on Linux and macOS. It uses [Bubble Tea](https://github.com/charmbracelet/bubbletea), [Bubbles](https://github.com/charmbracelet/bubbles), and [Lip Gloss](https://github.com/charmbracelet/lipgloss). VPN connections are handled by the OpenVPN binary installed on your system.

## Features

- Imports \`.ovpn\` profiles and copies referenced certificates, keys, CRLs, and TLS files into a private directory. Inline certificates and keys are preserved.
- Lists, renames, and deletes imported profiles.
- Runs one supervised OpenVPN process per profile through a persistent per-user daemon, \`ovpntuid\`. Closing the TUI does not disconnect active VPNs.
- Shows connection status, duration, PID, interface, assigned IP address, and session logs.
- Supports username/password authentication and optional storage through Secret Service.
- Supports browser-based WebAuth/OIDC SSO, including Zitadel, through OpenVPN's management interface.

## Requirements and installation

OpenVPN 2.x is required at runtime. Building from source requires Go 1.24 or newer. Run the TUI as your normal user; only OpenVPN is elevated through \`sudo\` or, on Linux, \`pkexec\`. Saving credentials requires \`secret-tool\` and an available Secret Service. You can connect without saving credentials.

On Debian or Ubuntu:

\`\`\`sh
sudo apt install openvpn libsecret-tools
\`\`\`

On macOS with Homebrew:

\`\`\`sh
brew install openvpn
\`\`\`

Install **both** binaries with Go:

\`\`\`sh
go install github.com/riken127/ovpntui/cmd/ovpntui@latest
go install github.com/riken127/ovpntui/cmd/ovpntuid@latest
ovpntui
\`\`\`

Make sure your Go binary directory is in \`PATH\`. To build from a checkout instead:

\`\`\`sh
make build
./bin/ovpntui
\`\`\`

\`make install\` installs both binaries to \`~/.local/bin\`. Set a different destination with \`make install INSTALL_DIR=/path/to/bin\`. Release archives include both binaries for Linux and macOS on \`amd64\` and \`arm64\`; keep them together or put both in \`PATH\`.

## Usage

| Key | Action |
| --- | --- |
| \`i\` | Import a local \`.ovpn\` file |
| \`enter\` | Connect or disconnect the selected profile |
| \`o\` | Connect using browser SSO/OIDC |
| \`l\` | View session logs |
| \`r\` | Rename a profile |
| \`d\` | Delete a profile, with confirmation |
| \`/\` | Filter profiles |
| \`q\` | Close the TUI while leaving VPN sessions running |

In the credentials form, press \`Enter\` to connect without saving the username and password, or \`Ctrl+S\` to save them in Secret Service before connecting. OpenVPN's temporary credentials file exists only during the session, has mode \`0600\`, and is removed afterward.

### Browser SSO

Select a profile and press \`o\`, or press \`Ctrl+O\` in the credentials form. After administrator authorization, complete the login in the browser and return to the TUI. The status shows \`waiting for browser SSO\` until authorization finishes.

This requires OpenVPN 2.5 or newer and a server configured for WebAuth/OIDC. The client advertises \`IV_SSO=webauth,openurl\` and receives \`AUTH_PENDING\` and \`WEB_AUTH\` over a private Unix socket. Only HTTPS URLs are opened. One-time authorization URLs and placeholder credentials are not persisted in application logs.

See the [OpenVPN management interface](https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt) and [openvpn-auth-oauth2 with Zitadel](https://github.com/jkroepke/openvpn-auth-oauth2/wiki/OpenVPN) for interoperability details.

### Daemon lifecycle

The first TUI launch starts \`ovpntuid\` in the background under your user account. It communicates through a private Unix socket. Reopening the TUI restores session status and logs.

After upgrading, a new TUI detects an incompatible running daemon. Disconnect active sessions with \`ovpntui --stop-daemon\`, then reopen the TUI to start the new daemon. Closing the TUI with \`q\` does not stop the daemon.

To disconnect all sessions and stop the daemon explicitly:

\`\`\`sh
ovpntui --stop-daemon
\`\`\`

Available command-line options:

\`\`\`text
--privilege=auto|sudo|pkexec|none
--openvpn=/path/to/openvpn
--stop-daemon
--version
\`\`\`

## Permissions and security

Do not run the TUI or daemon as root; the application refuses to do so. Only the OpenVPN child is elevated. When \`sudo\` needs authorization, the TUI requests the administrator password in a masked form, uses it once with \`sudo -S -v\`, and does not save or place it in process arguments.

The default \`auto\` mode uses cached \`sudo -n\` authorization when available. On a graphical Linux session, it can use \`pkexec\`; otherwise, the TUI asks for sudo authorization. In a terminal, you can authorize in advance with \`sudo -v\` and start with \`--privilege=sudo\`. The \`none\` mode is for OpenVPN installations that do not require elevation.

Imported profiles are validated again before execution. Directives that could run code or write arbitrary files as root, such as scripts, plugins, includes, custom management sockets, logging destinations, and daemonization, are rejected.

Application files follow XDG directories:

- \`$XDG_CONFIG_HOME/ovpntui/profiles/<id>/\`: imported profiles and assets;
- \`$XDG_RUNTIME_DIR/ovpntui/\`: daemon socket, lock, PID files, and temporary credentials;
- \`$XDG_STATE_HOME/ovpntui/logs/\`: persistent logs.

If \`XDG_RUNTIME_DIR\` is unset, a private \`$TMPDIR/ovpntui-<uid>/\` directory is used. Directories have mode \`0700\`; configuration, assets, metadata, logs, and temporary credentials have mode \`0600\`. An imported \`auth-user-pass\` file or inline credentials block is replaced by interactive credential entry.

## Troubleshooting

### Disconnects and network changes

The daemon requests shutdown through OpenVPN's private management channel, including when OpenVPN runs through \`sudo\` or \`pkexec\`. A session becomes \`disconnected\` only after the process exits without a reported cleanup error. If shutdown is not confirmed, it remains \`disconnecting\`, warns that routes may still be active, and prevents a second session for that profile.

The app sets a 10/30-second keepalive and overrides profile and server-pushed \`ping*\` timers. A timeout, management-channel loss, or another \`SIGUSR1\` restart terminates the session so OpenVPN can remove its routes, including profiles that use \`persist-tun\`. Once the network is available, connect the profile again; SSO may require another login.

This behavior allows traffic outside the VPN after cleanup; it is not a kill switch. Installing new binaries does not change an already running daemon.

### Common problems

- **\`openvpn is not installed\`**: install OpenVPN or pass \`--openvpn=/absolute/path\`.
- **sudo authorization required**: enter the administrator password in the masked form. On graphical Linux, \`--privilege=pkexec\` is another option.
- **\`ovpntuid is not installed\`**: install the daemon beside the TUI binary or elsewhere in \`PATH\`.
- **socket path is too long**: set \`XDG_RUNTIME_DIR\` to a shorter private directory.
- **profile rejected by security validation**: remove scripts, plugins, includes, custom logging or management, and daemonization directives.
- **TUN permission error**: check your privilege configuration and, on Linux, the availability of \`/dev/net/tun\`.
- **missing certificate or file**: import the profile from a directory containing all referenced files.
- **credentials are not saved**: install \`secret-tool\` and ensure Secret Service is unlocked, or connect without saving them.
- **authentication or TLS failure**: press \`l\` to inspect the session log.
- **\`AUTH_FAILED\` with a WebAuth profile**: connect with \`o\` or \`Ctrl+O\` and check the server's OIDC configuration.
- **browser does not open**: use the URL shown in the status bar and check that a browser opener is available.

## Contributing and development

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, project structure, and pull request guidance. When reporting a bug, include the operating system, OpenVPN version, reproduction steps, and logs with addresses, credentials, and tokens removed.

\`\`\`sh
make build
make check
make race
make fmt
make lint
\`\`\`

The integration tests use a simulated OpenVPN process and do not create real tunnels or routes. CI builds and runs the tests on Linux and macOS. \`make lint\` requires a local \`golangci-lint\` installation. Tags matching \`v*\` publish both binaries through GoReleaser.

## License

MIT. See [LICENSE](LICENSE).
