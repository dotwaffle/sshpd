# sshpd

sshpd relays an SSH byte stream through HTTPS and WebSockets.
The backend TCP connection survives a lost WebSocket connection.
SSH host-key verification and SSH authentication remain between the SSH client and sshd.

The project includes a passkey server, a resumable protocol client, and an OpenSSH ProxyCommand helper with a private credential agent.
Basic ChromeOS Terminal login and sleep/resume tests passed on a real device.
Exact browser replay during partial acceptance and Caddy reload remain untested.
Optional OpenTelemetry exports short operation spans and aggregate metrics.

## Packages

| Package | Responsibility |
| --- | --- |
| `protocol` | Encode and validate corp-relay-v4 commands |
| `relay` | Own TCP connections, SIDs, replay, quotas, revocation, and audit events |
| `client` | Expose a resumable byte stream with bounded replay |
| `internal/store` | Persist users, passkeys, invitations, and login grants |
| `internal/auth` | Verify WebAuthn ceremonies, approve native logins, and issue admission tickets |
| `internal/agent` | Keep native login credentials in memory behind a private Unix socket |
| `internal/nativeapi` | Define native approval, ticket, and transport messages |
| `internal/daemon` | Integrate relay discovery, login pages, reload, and private administration |
| `cmd/sshpd` | Run the server and private administration commands |
| `cmd/sshpc` | Approve native logins and connect OpenSSH through the relay |

The relay receives `Authorizer`, `Resolver`, `Dialer`, and `AuditSink` dependencies.
It does not import authentication or database packages.
Integrations own credential policy and storage.
SQL and generated sqlc types stay inside the store package.

## Build and check

Use Go 1.26 or later.
Development tools are configured in `mise.toml`.

```sh
mise install
mise run check
mise run generate
mkdir -p /tmp/build/sshpd/bin
go build -buildvcs=false -o /tmp/build/sshpd/bin/sshpd ./cmd/sshpd
go build -buildvcs=false -o /tmp/build/sshpd/bin/sshpc ./cmd/sshpc
```

`check` runs race tests, vet, lint, vulnerability checks, and a CGO-disabled build.
`generate` regenerates sqlc code from embedded migration schemas and queries.
The SQLite driver does not require cgo.

## CI and releases

GitHub Actions runs the full checks on branch pushes and pull requests.
It also runs race tests on Linux arm64 and macOS arm64.
CI cross-builds release archives without publishing them.

An existing `vMAJOR.MINOR.PATCH` tag triggers publication after all checks pass.
Tags can include a prerelease suffix, such as `v0.1.0-alpha.1`.
The workflow does not create tags.
It publishes a Linux amd64/arm64 image to `ghcr.io/dotwaffle/sshpd` with the exact version tag.
It does not update a `latest` image tag.
The workflow uses the repository's `GITHUB_TOKEN` and needs no registry secret.
The first GHCR package can require a manual visibility change before anonymous pulls work.

GitHub Releases receive compressed archives for Linux amd64/arm64, macOS arm64, and FreeBSD amd64.
Each archive contains `sshpd`, `sshpc`, a sample configuration, and build information.
The release includes SHA-256 checksums, archive sizes, and the container digest.
FreeBSD binaries are experimental until runtime acceptance passes.
Version-zero tags and tags with prerelease suffixes produce prereleases.
The workflow leaves automatic latest-release selection disabled.
Failed asset uploads leave a draft release for a workflow retry.

Binaries use GitHub Release storage instead of GitHub Packages storage.
The workflows do not upload temporary Actions artifacts.
GitHub currently provides free GHCR storage and bandwidth.
See [Packages billing](https://docs.github.com/en/billing/concepts/product-billing/github-packages) and [Release limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).

## Configure the server

Copy [examples/sshpd.json](examples/sshpd.json) to your configuration location.
Set the public HTTPS origin and RP ID before enrolling passkeys.
Use a persistent local volume for the state directory.
The directory must belong to the server UID and have mode 0700.

Keep local configuration and Compose files in `deploy/`.
Git ignores that directory.
The `examples/` directory contains public sample configuration.
The server creates a missing directory with that mode.
It rejects existing directories with broader permissions.

```sh
sshpd serve -config /etc/sshpd.json
```

The server runs database migrations before opening listeners.
Invalid configuration or migration errors stop startup.
HTTP listens on `127.0.0.1:8080` by default.
Use Caddy for public HTTPS on the same host.
See [examples/Caddyfile](examples/Caddyfile) for proxy and log-redaction configuration.
This example still needs validation with the deployed Caddy build.
For a container, set the internal listener and publish it only to the same-host proxy.

The RP ID must match the public origin's host or its parent domain.
Authentication ceremonies run on the public origin.
`terminal_origins` permits exact origins for relay discovery and WebSocket connections.
Its default is `chrome-untrusted://terminal`.
It does not permit passkey ceremonies on those origins.

The configuration decoder rejects unknown fields and extra JSON values.
Timeouts use strings such as `"15m"`.
A target accepts only configured host and port pairs.
A missing port defaults to 22.
Aliases share a stable destination ID, even when the backend uses a different address or port.

Send SIGHUP after replacing the configuration file.
Reload permits changes only to `destinations` and `drop_removed`.
Invalid reloads preserve the current destination list.
The default drains existing streams and preserves their SIDs.
`drop_removed: true` closes removed or retargeted streams.
Every reload fences pending admissions and dials.

## Enroll and manage passkeys

Administration uses `<state_dir>/admin.sock`.
The socket has mode 0600.
The listener checks the peer UID with the operating system.
The public HTTP server has no administration route.

```sh
sshpd admin -socket /var/lib/sshpd/admin.sock user-add alice
sshpd admin -socket /var/lib/sshpd/admin.sock users
sshpd admin -socket /var/lib/sshpd/admin.sock user-invite alice
sshpd admin -socket /var/lib/sshpd/admin.sock key-remove alice KEY_ID
sshpd admin -socket /var/lib/sshpd/admin.sock user-disable alice
sshpd admin -socket /var/lib/sshpd/admin.sock user-recover alice
sshpd admin -socket /var/lib/sshpd/admin.sock user-delete alice
```

`user-add`, `user-invite`, and `user-recover` return an enrollment link in JSON.
Send that link directly to the user.
Its secret is in the URL fragment, so HTTP requests do not contain it.
The page removes the fragment from the address bar after reading it.
Each user can have one active invitation.
A replacement invitation invalidates the previous one.
Page access and failed registration do not consume the invitation.
Successful registration consumes it in the same transaction that stores the key.

Adding a passkey preserves other keys and logins.
Removing a passkey revokes its logins and their relay streams.
Other keys and logins remain active.
Disabling or deleting a user closes all attached and detached streams for that user.
Recovery revokes old keys, logins, invitations, and streams, then enables a new enrollment.

Device-bound and synced passkeys are supported.
User verification is required by default.
`allow_no_uv: true` enables an operator-selected compatibility mode.
Both modes verify challenge, origin, RP ID, signature, and user presence.
Authentication logs omit assertions and credential secrets.

## Connect from ChromeOS Terminal

Use these relay options with your saved SSH destination:

```text
--proxy-host=relay.example.com --proxy-port=443 --proxy-mode=corp-relay-v4@google.com --relay-method=direct --relay-protocol=v2 --use-ssl --resume-connection
```

The server provides `/endpoint`, `/cookie?version=2&method=direct`, and the authenticated `close` popup flow.
Discovery JSON starts with the five-byte XSSI prefix expected by libapps.
Browser cookies use Secure, HttpOnly, and SameSite=None.
Login expiry blocks new streams without renewing the login.
Existing streams and SID resumes remain valid until explicit revocation or relay retention ends.
Signing out closes streams from that login only.
The browser profile cookie keeps the replacement identity stable across logins.

Device acceptance must cover popup/CORS behavior, lid-close/wake, loss in both directions, and Caddy reload.
The cached upstream libapps source shows replay and clean-close behavior that can limit browser resumes.
The native protocol client has independent replay tests.

## Relay lifetime and limits

| Setting | Default |
| --- | --- |
| Browser and native admission lifetime (`login_ttl`) | 12 hours |
| Enrollment invitation lifetime | 15 minutes |
| Passkey ceremony lifetime | 5 minutes |
| Native approval lifetime (`approval_ttl`) | 5 minutes |
| Native ticket lifetime (`ticket_ttl`) | 30 seconds |
| Detached stream retention | 15 minutes |
| Total sessions | 1024 |
| Sessions per user | 32 |
| Replay bytes per session | 1 MiB |
| Aggregate replay allocation | Smaller of 64 MiB or 10% of a finite Go memory limit |
| Minimum detached age for pressure eviction | 1 minute |
| Fresh-connection replacement age | More than 1 minute detached |

Replay buffers grow on demand.
At the cap, the reader applies backpressure without discarding required bytes.
Attached and detached replay allocations count toward the aggregate budget.
Resume retains the same session slot and backend TCP connection.
A fresh successful backend dial can replace older detached streams.
Replacement matches the user, client identity, and destination ID.
Attached streams coexist.
Failed dials preserve replacement candidates.

Pressure eviction starts at 80% and targets 70% of a finite Go memory limit.
It selects eligible detached sessions by largest allocation, then oldest age.
`oldest_first` changes that order.
Attached sessions remain protected.
The manager credits released allocations while waiting for garbage collection.
If no victim is eligible, the relay applies backpressure and rejects new admissions.

The standalone startup applies automemlimit once.
It respects an explicit `GOMEMLIMIT`.
The relay library does not change runtime memory limits.
No SID, backend stream, or transient passkey ceremony survives a server restart.

## Native protocol library

`client.Open` accepts a relay URL, destination, initial admission headers, and a lifetime context.
The returned `Conn` implements `io.Reader`, `io.Writer`, and `io.Closer`.
One reader and one writer can use it concurrently.
Cancellation releases blocked reads, writes, and reconnect attempts.

Initial headers are used once.
The native HTTP and WebSocket transports reject redirects.
Reconnect uses only the SID and byte offsets.
It does not repeat admission or create a fresh backend connection after SID loss.
ACK validation rejects offsets beyond bytes offered to the transport.
Unacknowledged outgoing bytes replay from the server's accepted offset.
Buffered incoming bytes are acknowledged for resume and delivered before terminal errors.

`Conn.Flush(ctx)` waits for acknowledgment of queued output.
It does not confirm backend delivery or send an SSH disconnect.

## Connect with OpenSSH

The native helper supports Linux, macOS, and Linux inside ChromeOS Crostini.
Install `sshpc` on your PATH, then start an explicit login:

```sh
sshpc login --server https://relay.example.com
```

This command starts the private agent if needed.
It prints an approval URL, code, installation ID, and deadline.
Open the URL on a device with your passkey.
Approve only a login you started, after comparing its code and installation ID with your command line.
The command does not open a browser.
Approval expires after five minutes by default.
The polling proof remains in the agent and prevents another client from collecting the login grant.

Use the helper as an OpenSSH ProxyCommand:

```sh
ssh -o 'ProxyCommand=sshpc proxy --server https://relay.example.com --host %h --port %p' alice@home.example.com
```

The host and port must match a configured destination alias.
OpenSSH verifies the host key and performs SSH authentication through its existing SSH agent.
`sshpc` uses a separate socket and does not change `SSH_AUTH_SOCK`.
ProxyCommand writes only SSH bytes to stdout.
It never starts a login or opens a browser.

```sh
sshpc status --server https://relay.example.com
sshpc logout --server https://relay.example.com
```

The default socket is `~/.ssh/sshpd/agent.sock`.
Use `--agent-socket /absolute/private/path/agent.sock` on each command to override it.
The directory must belong to your UID with mode 0700.
The socket, lock file, and non-secret installation ID file have mode 0600.
Both peers check the other process's UID.
The installation ID survives agent restarts.
Bearers and polling proofs remain in memory and never enter the local API or files.
Run `sshpc agent --agent-socket /absolute/private/path/agent.sock` in the foreground to inspect startup failures.

Fresh connections obtain one-use tickets bound to the canonical destination and current login.
Tickets expire after 30 seconds by default, or sooner when the admission grant expires.
Admission grants expire after 12 hours by default, with no automatic renewal.
Local status reports cached expiry.
A fresh ticket request also checks server revocation.
Logout revokes the current native login and its streams, including after admission expiry.
It preserves other logins.

After admission, the helper owns its SID and replay buffers.
Agent loss does not terminate an established stream or its reconnect attempts.
New connections require another explicit login after agent loss or reboot.
Resume uses only the SID and byte offsets, without another ticket or passkey prompt.
The default retry window is 15 minutes with bounded jittered backoff.
Use `--resume-window 15m` on `sshpc proxy` to set that window.
Definitive SID loss ends the helper without creating another backend.
Server restart ends existing streams and SIDs.

## Audit and proxy logs

The relay emits typed, unsampled lifecycle events.
Their session IDs are audit correlation IDs, separate from protocol SIDs.
Events include ownership, destination, backend address, byte counts, and close reasons.
They omit SIDs, cookies, tokens, assertions, and SSH payloads.

The default sink writes structured slog records.
The asynchronous queue is bounded and preserves enqueue order.
Queue overflow and sink failure increment `Stats.AuditLost` and emit loss diagnostics.
A successful `Record` means sink acceptance, not crash durability.
Shutdown drains within one audit timeout and counts remaining losses.
`Close` waits for that drain.
Audit callbacks must honor cancellation.

The default failure policy preserves service and existing streams.
`strict_audit` rejects a new admission if its start event cannot be recorded.
It does not close unrelated existing streams.

Configure Caddy to remove request URIs and credential headers from access and error logs.
The reconnect query contains a sensitive SID.
Do not enable Caddy's `log_credentials` option.
`stream_close_delay` can postpone closure during Caddy reload.
It cannot establish browser resume correctness.
See the [Caddy logging documentation](https://caddyserver.com/docs/caddyfile/directives/log) and [streaming proxy settings](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#streaming).

The server ignores forwarding headers by default.
Set `trusted_proxies` to the IPv4 or IPv6 CIDRs of the proxies that connect to the relay.
For example, use `["192.0.2.10/32"]` for one proxy address.
Trust only networks whose members you control.
Changes require a restart.

For a trusted transport peer, the server reads `X-Forwarded-For` from right to left.
It stops at the first address outside the configured proxy networks.
Malformed or oversized chains fall back to the transport peer.
The server ignores `X-Real-IP`, which Caddy does not set by default.
Audit events include the validated client IP and the transport peer IP.
These addresses are diagnostic fields, not admission credentials or metric labels.
Exempt the actual relay backend source address from sshd fail2ban rules where required.
In a container, that address can be the Docker bridge address.
The relay cannot inspect encrypted SSH authentication failures.

## Telemetry

Telemetry is disabled by default.
Set `"telemetry": {"enabled": true, "sample_ratio": 0.1}` in the server configuration to enable OTLP HTTP export.
Changes require a restart.
The sampling ratio accepts zero through one and defaults to 0.1.
Zero disables sampled traces but preserves metrics and audit events.

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to the collector's base URL.
The HTTP exporters append `/v1/traces` and `/v1/metrics`.
Signal-specific endpoints and authentication headers use the standard `OTEL_EXPORTER_OTLP_TRACES_*` and `OTEL_EXPORTER_OTLP_METRICS_*` environment variables.
Use HTTPS for remote collectors.
Keep collector credentials outside the repository.
`OTEL_METRIC_EXPORT_INTERVAL` sets the metric interval in milliseconds, with a default of 60000.
The server limits each export to five seconds.

The daemon passes explicit providers to the relay and store.
Embedded relays can supply `TracerProvider` and `MeterProvider` through `relay.Config`.
The server does not install global providers or accept incoming trace or baggage headers.
Its resource contains only `service.name=sshpd`.

Spans cover HTTP authentication, admission, backend dialing, reconnect, lifecycle events, and SQLite transaction phases.
Connect and reconnect spans end before stream handling starts.
Reconnect and lifecycle spans link to the initial connect span.
Spans omit identities, destinations, IPs, SIDs, URLs, headers, credentials, and stream contents.
Logs can include internal trace IDs and validated client and peer IPs.
Audit records retain their documented ownership fields independently of trace sampling.

| Metric | Meaning |
| --- | --- |
| `sshpd.operations` | Operation count by fixed operation and outcome |
| `sshpd.operation.duration` | Operation duration in seconds |
| `sshpd.relay.sessions` | Attached and detached session counts |
| `sshpd.relay.dialing` | Pending admissions and backend dials |
| `sshpd.relay.replay.capacity` | Allocated replay capacity in bytes |
| `sshpd.relay.audit.lost` | Dropped or rejected audit events |
| `sshpd.sqlite.busy` | Retried SQLite busy errors |
| `sshpd.sqlite.pool.connections` | Open SQLite connections |
| `sshpd.sqlite.pool.waits` | Cumulative waits for a pooled connection |
| `sshpd.sqlite.pool.wait.duration` | Cumulative pool wait time in seconds |
| `sshpd.sqlite.wal.size` | Current WAL file size in bytes |

Metric labels contain fixed operation, outcome, or session state values.
Each instrument permits at most 64 attribute sets.
The trace queue holds at most 256 spans and exports batches of at most 64 spans.
Queue saturation can discard traces.
Collector failures produce generic diagnostics and do not change admission or resume policy.
Telemetry does not replace audit storage or provide crash durability.
Shutdown drains telemetry within one five-second deadline.

## Storage and backups

Use the [operations procedure](docs/operations.md) for upgrade, restore, and rollback preparation.

SQLite uses WAL, a 5000 ms busy timeout, foreign keys, and synchronous FULL on every connection.
Startup reads those values back before migrations.
The pool starts with one open and one idle connection.
Read-modify-write transactions use IMMEDIATE mode and bounded retries of typed busy errors.
Account generations and credential versions fence stale ceremonies and concurrent assertions.
Network verification occurs outside transactions.
Expired invitation rows are pruned once per minute.
Login hashes and IDs remain available for passkey revocation while streams can exist, even after admission expiry.
Expired native logins also retain their scoped logout authority.
Logout, revocation, or server startup removes these expired login records.
Startup preserves grants that have not expired.
Expired approvals discard uncollected grants, and expired tickets are removed.

```sh
sshpd admin -socket /var/lib/sshpd/admin.sock backup before-update
```

The result identifies `<state_dir>/backups/before-update.db`.
The backup keeps users and passkeys but removes login grants and invitations.
Current logins and relay streams remain active.
Existing snapshot files are preserved.
Only completed snapshots are published.
Do not restore `.partial` files left by a terminated backup.

The copy uses SQLite's [consistent VACUUM INTO snapshot](https://www.sqlite.org/lang_vacuum.html#vacuum_with_an_into_clause).
Grant removal completes before publication.
To restore, stop the server and replace its database with a completed backup.
Preserve ownership and mode 0600.
Reapply later user and key revocations before exposing the restored server.
Restored users must sign in again and receive new enrollment invitations where needed.
Do not restore a live filesystem copy that contains old grants.

Goose runs embedded, zero-padded migrations through a Provider instance.
There is no migration administration command.
The pinned SQLite version includes the WAL-reset fix.
The module uses the libc version required by that driver.

## Protocol reference

The implementation follows the [libapps relay protocol](https://chromium.googlesource.com/apps/libapps/+/HEAD/nassh/docs/relay-protocol.md).
It supports corp-relay-v4 WebSockets with the `ssh` subprotocol and cookie-v2 direct/close discovery.
Legacy XHR transport is outside the current scope.
