# Upgrade, restore, and rollback

Use an approved maintenance window for changes to a running server.
This procedure does not change the proxy configuration.
Keep the public origin, RP ID, destination aliases, and state ownership unchanged.
Record the current image digest, configuration, server UID, and database schema version before an upgrade.
Keep the old image available until acceptance tests pass.

## Prepare the state

Stop the server before an offline snapshot or database replacement.
A server restart ends all relay streams and invalidates their SIDs.
The native credential agent cannot restore those streams.

Use SQLite to make a consistent snapshot, including any committed WAL contents.
Do not copy only `admission.db` from a database that has a WAL file.
For Docker volumes, first make the stopped volume accessible to the maintenance process.
Run the commands as the state owner, or preserve the recorded UID when copying files.

The following commands require `sqlite3` and an accessible state directory.
Replace the two example paths before use.
Use a new snapshot filename for each maintenance window.

```sh
state_dir=/var/lib/sshpd
backup_dir=/var/backups/sshpd
umask 077
mkdir -p "$backup_dir"
chmod 700 "$backup_dir"
sqlite3 "$state_dir/admission.db" 'SELECT max(version_id) FROM goose_db_version WHERE is_applied=1;'
test ! -e "$backup_dir/before-upgrade.db"
sqlite3 "$state_dir/admission.db" "VACUUM INTO '$backup_dir/before-upgrade.db';"
sqlite3 "$backup_dir/before-upgrade.db" 'PRAGMA synchronous=FULL; BEGIN IMMEDIATE; DELETE FROM logins; DELETE FROM invitations; COMMIT;'
chmod 600 "$backup_dir/before-upgrade.db"
sqlite3 "$backup_dir/before-upgrade.db" 'PRAGMA integrity_check; SELECT count(*) FROM logins; SELECT count(*) FROM invitations; SELECT max(version_id) FROM goose_db_version WHERE is_applied=1;'
```

Require `ok`, zero logins, zero invitations, and the original schema version from the last command.
Keep the snapshot and its metadata outside the live state volume.
Copy it to your existing backup storage with private permissions.
The snapshot preserves accounts, passkeys, account generations, and credential counters.
It removes bearer grants so a restore requires a new sign-in.

Keep this snapshot at its original schema version.
Do not open it with the new server before a rollback.
The new server migrates databases when it opens them.
An online `sshpd admin ... backup` uses that server's current schema.
It does not provide an older schema for an older binary.

## Upgrade

1. Build or obtain the approved image and record its digest.
2. Confirm its UID matches the owner of the private state directory.
3. Retain the old image and the completed snapshot.
4. Update only the server image and approved server configuration.
5. Start the server with the existing state volume and proxy routing labels.
6. Check startup logs for migration and listener errors.
7. Check the private admin socket for the expected users and key identifiers.
8. Complete passkey, native login, reconnect, logout, and revocation acceptance tests.

The native login migration adds `kind` and `client_id` columns to existing logins.
Existing grants receive `kind=terminal` and an empty client ID.
Startup removes expired grants and retains unexpired grants.
No migration changes passkey data or counters.

Keep the HTTP listener accessible only to the configured proxy network.
The state directory requires mode 0700.
The database and private admin socket require mode 0600.
Keep the container read-only, with its existing capability and resource limits.
Configure trusted proxy CIDRs to cover only controlled proxy peers.
Optional telemetry needs an explicit collector configuration before enablement.

## Restore with the current image

1. Stop the server and confirm it has exited.
2. Retain the failed database and its WAL and SHM files outside the live state directory.
3. Install a completed, sanitized snapshot as `admission.db` in an empty private state directory.
4. Restore the server UID and database mode 0600.
5. Start the current image against the restored state.
6. Verify users, passkeys, disabled accounts, and credential counters through the private administration interface and database.
7. Reapply account and key revocations made after the snapshot.
8. Require new sign-ins and replace any required enrollment invitations.

Do not leave WAL or SHM files from another database beside the restored snapshot.
Do not restore a `.partial` file or a filesystem copy that retains login grants.
Older credential counters can require passkey recovery after later authentications.
Resolve those changes before exposing the restored server publicly.

## Rollback with the old image

Use the pre-upgrade snapshot and the recorded old image digest.
Do not run a downgrade migration on the upgraded live database.
Do not assume an old server can open a newer schema.

Follow the restore steps with the old image and the original configuration.
Reapply later revocations and account changes before public access.
Native login data created after the upgrade will not exist in the old snapshot.
Require new browser sign-ins after rollback.
Retain the failed upgraded database privately until the rollback review finishes.

## Local rehearsal

The store test creates a synthetic version-one database with an account, a passkey counter, and an unexpired browser grant.
It checks migration defaults, native grant creation, current-schema backup restore, and sanitized version-one rollback data.
It does not access a production database or issue a real credential.

```sh
mise exec -- go test -race ./internal/store -run TestLegacyUpgradeRestoreAndRollbackRehearsal -v
```
