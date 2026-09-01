# Keeplock

**Deliberate hand-offs for developers who work across devices.**

Keeplock lets you publish a scratchpad from one terminal and mirror it onto others, without Git or a background sync service. Each namespace on the central server has one owning Keeplock identity key. From another device, you can clone or pull that namespace as a read-only mirror.

Keeplock has no server component. The server only needs to accept SSH connections, and all Keeplock state lives under `.keeplock` in the remote SSH user's home directory.

## Installation

```bash
pip install keeplock
```

Keeplock requires the SSH server to provide an SFTP subsystem (the default on OpenSSH). It uses `paramiko` for the SSH connection and SFTP transfer.

## How it works

A **namespace** is a directory stored on the server. Its name is also the name of its local directory. Each namespace is bound to exactly one owning Keeplock identity key, identified by the fingerprint:

```text
sha256-<lowercase-hex-sha256-of-the-identity-public-key-blob>
```

Server storage:

```text
.keeplock/
  sha256-<identity-fingerprint>/
    <namespace>/
```

The Keeplock identity key is independent of the SSH credential used to access the server.

## Usage

Every command supplies exactly one SSH server-access option:

```text
--ed25519-key <path> | --rsa-key <path> | --password <password>
```

`--ed25519-key` and `--rsa-key` take a path to the private key used to access the SSH server. `--password` takes the SSH server password as its value.

A command may also supply at most one Keeplock identity option:

```text
--identity-ed25519-key <path> | --identity-rsa-key <path>
```

`--identity-ed25519-key` and `--identity-rsa-key` take a path to the Keeplock identity key that determines namespace ownership. When neither is given, Keeplock looks for `~/.ssh/id_ed25519` and then `~/.ssh/id_rsa`.

In the command synopses below, `(...)` marks a required choice (pick exactly one) and `[...]` marks an optional argument.

### Create a namespace

```text
keeplock init <name> --host <host> [--port <port>] --username <username> \
    (--ed25519-key <path> | --rsa-key <path> | --password <password>) \
    [--identity-ed25519-key <path> | --identity-rsa-key <path>]
```

`<name>`, `--host`, and `--username` are required; `--port` is optional (default `22`). Exactly one of the server-access options is required, and the identity option is optional.

For example:

```bash
keeplock init phone --host server.example.com --username user --ed25519-key ~/.ssh/server_access_ed25519
```

This creates the remote namespace, binds it to the Keeplock identity key, and creates `./phone` containing only `.keeplock.json`:

```json
{
  "host": "server.example.com",
  "port": 22,
  "username": "user"
}
```

`.keeplock.json` holds only the server connection details; it never stores server-access credentials or Keeplock identity keys.

### List namespaces

```text
keeplock ls --host <host> [--port <port>] --username <username> \
    (--ed25519-key <path> | --rsa-key <path> | --password <password>) \
    [--identity-ed25519-key <path> | --identity-rsa-key <path>]
```

`--host` and `--username` are required; `--port` is optional (default `22`). Exactly one of the server-access options is required, and the identity option is optional.

For example:

```bash
keeplock ls --host server.example.com --username user --ed25519-key ~/.ssh/server_access_ed25519
```

```text
write:      phone
read-only:  laptop
read-only:  termux
```

### Publish the current tree

Run inside a namespace directory:

```text
keeplock push [-d | --dry-run] \
    (--ed25519-key <path> | --rsa-key <path> | --password <password>) \
    [--identity-ed25519-key <path> | --identity-rsa-key <path>]
```

Exactly one of the server-access options is required. `-d`/`--dry-run` and the identity option are optional. `--host`, `--port`, and `--username` are read from `.keeplock.json`.

For example:

```bash
keeplock push --ed25519-key ~/.ssh/server_access_ed25519
```

```text
Verifying this Keeplock identity key owns "phone"... ok
Mirroring server tree to match local... done
remote: tree updated
```

Use `-d`/`--dry-run` to report the changes without making them.

### Clone a mirror

```text
keeplock clone <name> --host <host> [--port <port>] --username <username> \
    (--ed25519-key <path> | --rsa-key <path> | --password <password>) \
    [--identity-ed25519-key <path> | --identity-rsa-key <path>]
```

`<name>`, `--host`, and `--username` are required; `--port` is optional (default `22`). Exactly one of the server-access options is required, and the identity option is optional.

For example:

```bash
keeplock clone phone --host server.example.com --username user --ed25519-key ~/.ssh/server_access_ed25519
```

If the current Keeplock identity key does not own the namespace, the clone is a read-only mirror.

### Pull the current tree

Run inside a namespace directory:

```text
keeplock pull [-d | --dry-run] \
    (--ed25519-key <path> | --rsa-key <path> | --password <password>) \
    [--identity-ed25519-key <path> | --identity-rsa-key <path>]
```

Exactly one of the server-access options is required. `-d`/`--dry-run` and the identity option are optional. `--host`, `--port`, and `--username` are read from `.keeplock.json`.

For example:

```bash
keeplock pull --ed25519-key ~/.ssh/server_access_ed25519
```

`pull` updates the local mirror to match the server tree. Local files not present on the server are removed. Use `-d`/`--dry-run` to report the changes without making them.

## Notes

- `push` and `pull` read the server connection details from `.keeplock.json` and the namespace name from the current directory name.
- `push` and `pull` compare each file's size and modification time, so unchanged files are not re-transferred. Transfers preserve modification times to keep later syncs fast.
- Keeplock mirrors regular files and directories. Symbolic links and other special files are ignored.
- A namespace found under multiple identity directories is an error; manual server cleanup is required.

## Running the tests

From the project root:

```bash
python -m unittest discover -s tests -t .
```

The tests exercise the namespace scanner, the push/pull tree synchronization engine, configuration round-trips, change records, and argument parsing.

## Contributing

Contributions are welcome! Please submit pull requests or open issues on the GitHub repository.

## License

This project is licensed under the [MIT License](LICENSE).
