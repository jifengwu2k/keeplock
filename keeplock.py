#!/usr/bin/env python
# Copyright (c) 2026 Jifeng Wu
# Licensed under the MIT License. See LICENSE file in the project root for full license information.
"""Keeplock: deliberate, read-only-mirrorable scratchpad hand-offs over SSH."""

from __future__ import print_function

import argparse
import codecs
import hashlib
import json
import os
import socket
import stat
import sys

from typing import Dict, List, Optional, Tuple, Union

import paramiko  # type: ignore[import-untyped]

if sys.version_info[0] == 2:
    TEXT_TYPE = unicode  # type: ignore[name-defined]
else:
    TEXT_TYPE = str


def open_text(path, mode):
    # type: (str, str) -> object
    if sys.version_info[0] == 2:
        return codecs.open(path, mode, "utf-8")
    return open(path, mode, encoding="utf-8")


KEEPLOCK_META_DIR = ".keeplock"
LOCAL_CONFIG_FILENAME = ".keeplock.json"
DEFAULT_ED25519_IDENTITY = os.path.join(
    os.path.expanduser("~"), ".ssh", "id_ed25519"
)
DEFAULT_RSA_IDENTITY = os.path.join(
    os.path.expanduser("~"), ".ssh", "id_rsa"
)

AuthValue = Union[str, paramiko.PKey]
Auth = Tuple[str, AuthValue]


class Change(object):
    __slots__ = ("rel",)

    verb = ""  # type: str

    def __init__(self, rel):
        # type: (str) -> None
        self.rel = rel  # type: str


class AddChange(Change):
    __slots__ = ()
    verb = "add"


class UpdateChange(Change):
    __slots__ = ()
    verb = "update"


class DeleteChange(Change):
    __slots__ = ()
    verb = "delete"


class MkdirChange(Change):
    __slots__ = ()
    verb = "mkdir"


class KeeplockError(Exception):
    __slots__ = ()


def expand_user_path(path):
    # type: (str) -> str
    return os.path.expanduser(path)


def validate_namespace_name(name):
    # type: (str) -> None
    if not name:
        raise KeeplockError("namespace name must not be empty")
    if name in (".", ".."):
        raise KeeplockError('invalid namespace name "%s"' % (name,))
    if "/" in name or "\\" in name:
        raise KeeplockError(
            'invalid namespace name "%s": path separators are not allowed' % (name,)
        )


def identity_fingerprint(key):
    # type: (paramiko.PKey) -> str
    return "sha256-" + hashlib.sha256(key.asbytes()).hexdigest()


def load_server_auth(args):
    # type: (argparse.Namespace) -> Auth
    if args.password is not None:
        return ("password", args.password)
    if args.ed25519_key is not None:
        return (
            "key",
            paramiko.Ed25519Key.from_private_key_file(
                expand_user_path(args.ed25519_key)
            ),
        )
    if args.rsa_key is not None:
        return (
            "key",
            paramiko.RSAKey.from_private_key_file(
                expand_user_path(args.rsa_key)
            ),
        )
    raise KeeplockError("no server access option supplied")


def load_identity_key(args):
    # type: (argparse.Namespace) -> paramiko.PKey
    if args.identity_ed25519_key is not None:
        return paramiko.Ed25519Key.from_private_key_file(
            expand_user_path(args.identity_ed25519_key)
        )
    if args.identity_rsa_key is not None:
        return paramiko.RSAKey.from_private_key_file(
            expand_user_path(args.identity_rsa_key)
        )
    if os.path.exists(DEFAULT_ED25519_IDENTITY):
        return paramiko.Ed25519Key.from_private_key_file(DEFAULT_ED25519_IDENTITY)
    if os.path.exists(DEFAULT_RSA_IDENTITY):
        return paramiko.RSAKey.from_private_key_file(DEFAULT_RSA_IDENTITY)
    raise KeeplockError(
        "no Keeplock identity key found; provide --identity-ed25519-key or "
        "--identity-rsa-key, or place one at %s or %s"
        % (DEFAULT_ED25519_IDENTITY, DEFAULT_RSA_IDENTITY)
    )


def server_connection_from_args(args):
    # type: (argparse.Namespace) -> Tuple[str, int, str]
    if args.host is None or args.username is None:
        raise KeeplockError("--host and --username are required")
    return args.host, args.port, args.username


def close_transport_socket(transport, sock):
    # type: (Optional[paramiko.Transport], Optional[socket.socket]) -> None
    if transport is not None:
        try:
            transport.close()
        except Exception:
            pass
    if sock is not None:
        try:
            sock.close()
        except Exception:
            pass


def close_connection(transport, sftp):
    # type: (Optional[paramiko.Transport], Optional[paramiko.SFTPClient]) -> None
    if sftp is not None:
        try:
            sftp.close()
        except Exception:
            pass
    if transport is not None:
        try:
            transport.close()
        except Exception:
            pass


def connect_sftp(host, port, username, auth):
    # type: (str, int, str, Auth) -> Tuple[paramiko.Transport, paramiko.SFTPClient]
    sock = None  # type: Optional[socket.socket]
    transport = None  # type: Optional[paramiko.Transport]
    try:
        sock = socket.create_connection((host, port))
        transport = paramiko.Transport(sock)
        transport.start_client()
        auth_kind, auth_value = auth
        if auth_kind == "password":
            transport.auth_password(username, auth_value)
        else:
            transport.auth_publickey(username, auth_value)
        if not transport.is_authenticated():
            raise KeeplockError("SSH authentication failed")
        sftp = paramiko.SFTPClient.from_transport(transport)
        return transport, sftp
    except paramiko.AuthenticationException as error:
        close_transport_socket(transport, sock)
        raise KeeplockError("SSH authentication failed: %s" % (error,))
    except paramiko.SSHException as error:
        close_transport_socket(transport, sock)
        raise KeeplockError("SSH error: %s" % (error,))
    except KeeplockError:
        close_transport_socket(transport, sock)
        raise
    except Exception as error:
        close_transport_socket(transport, sock)
        raise KeeplockError(
            "could not connect to %s:%s: %s" % (host, port, error)
        )


def remote_path_exists(sftp, path):
    # type: (paramiko.SFTPClient, str) -> bool
    try:
        sftp.stat(path)
        return True
    except (IOError, OSError):
        return False


def ensure_remote_dir(sftp, path):
    # type: (paramiko.SFTPClient, str) -> None
    current = ""
    for part in path.split("/"):
        if part == "":
            continue
        current = part if current == "" else current + "/" + part
        if not remote_path_exists(sftp, current):
            sftp.mkdir(current)


def identity_dir_path(fingerprint):
    # type: (str) -> str
    return "%s/%s" % (KEEPLOCK_META_DIR, fingerprint)


def namespace_remote_path(fingerprint, namespace):
    # type: (str, str) -> str
    return "%s/%s/%s" % (KEEPLOCK_META_DIR, fingerprint, namespace)


def scan_namespaces(sftp):
    # type: (paramiko.SFTPClient) -> Dict[str, List[str]]
    result = {}  # type: Dict[str, List[str]]
    if not remote_path_exists(sftp, KEEPLOCK_META_DIR):
        return result
    try:
        identity_entries = sftp.listdir_attr(KEEPLOCK_META_DIR)
    except (IOError, OSError):
        return result
    for identity_entry in identity_entries:
        if not stat.S_ISDIR(identity_entry.st_mode):
            continue
        fingerprint = identity_entry.filename
        identity_dir = identity_dir_path(fingerprint)
        try:
            namespace_entries = sftp.listdir_attr(identity_dir)
        except (IOError, OSError):
            continue
        for namespace_entry in namespace_entries:
            if not stat.S_ISDIR(namespace_entry.st_mode):
                continue
            namespace = namespace_entry.filename
            if namespace not in result:
                result[namespace] = []
            result[namespace].append(fingerprint)
    for namespace in result:
        result[namespace].sort()
    return result


def find_namespace_owner(sftp, namespace):
    # type: (paramiko.SFTPClient, str) -> Optional[str]
    namespaces = scan_namespaces(sftp)
    owners = namespaces.get(namespace)
    if not owners:
        return None
    if len(owners) > 1:
        raise KeeplockError(
            'namespace "%s" exists under multiple identities; manual server '
            "cleanup is required." % (namespace,)
        )
    return owners[0]


def read_local_config(cwd):
    # type: (str) -> Tuple[str, int, str]
    path = os.path.join(cwd, LOCAL_CONFIG_FILENAME)
    if not os.path.isfile(path):
        raise KeeplockError(
            "no %s found in %s; run init or clone first"
            % (LOCAL_CONFIG_FILENAME, cwd)
        )
    try:
        with open_text(path, "r") as stream:
            data = json.loads(stream.read())
    except (IOError, OSError) as error:
        raise KeeplockError("could not read %s: %s" % (path, error))
    except ValueError as error:
        raise KeeplockError("invalid JSON in %s: %s" % (path, error))

    host = data.get("host")
    port = data.get("port")
    username = data.get("username")
    if not isinstance(host, TEXT_TYPE) or not host:
        raise KeeplockError('missing or invalid "host" in %s' % (path,))
    if not isinstance(username, TEXT_TYPE) or not username:
        raise KeeplockError('missing or invalid "username" in %s' % (path,))
    if isinstance(port, bool) or not isinstance(port, int):
        raise KeeplockError('missing or invalid "port" in %s' % (path,))
    return host, port, username


def write_local_config(path, host, port, username):
    # type: (str, str, int, str) -> None
    data = {"host": host, "port": port, "username": username}
    try:
        with open_text(path, "w") as stream:
            stream.write(json.dumps(data, indent=2))
            stream.write("\n")
    except (IOError, OSError) as error:
        raise KeeplockError("could not write %s: %s" % (path, error))


def list_local_entries(abs_dir):
    # type: (str) -> Dict[str, str]
    result = {}  # type: Dict[str, str]
    for name in os.listdir(abs_dir):
        child = os.path.join(abs_dir, name)
        if os.path.islink(child):
            continue
        if os.path.isdir(child):
            result[name] = "dir"
        elif os.path.isfile(child):
            result[name] = "file"
    return result


def list_remote_entries(sftp, abs_dir):
    # type: (paramiko.SFTPClient, str) -> Dict[str, str]
    result = {}  # type: Dict[str, str]
    for entry in sftp.listdir_attr(abs_dir):
        if stat.S_ISLNK(entry.st_mode):
            continue
        if stat.S_ISDIR(entry.st_mode):
            result[entry.filename] = "dir"
        elif stat.S_ISREG(entry.st_mode):
            result[entry.filename] = "file"
    return result


def hash_local_file(path):
    # type: (str) -> str
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def hash_remote_file(sftp, path):
    # type: (paramiko.SFTPClient, str) -> str
    digest = hashlib.sha256()
    with sftp.open(path, "rb") as stream:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def files_differ(sftp, local_path, remote_path):
    # type: (paramiko.SFTPClient, str, str) -> bool
    if os.path.getsize(local_path) != sftp.stat(remote_path).st_size:
        return True
    return hash_local_file(local_path) != hash_remote_file(sftp, remote_path)


def remove_local(path):
    # type: (str) -> None
    if os.path.islink(path) or os.path.isfile(path):
        os.remove(path)
        return
    if os.path.isdir(path):
        for name in os.listdir(path):
            remove_local(os.path.join(path, name))
        os.rmdir(path)


def remove_remote(sftp, path):
    # type: (paramiko.SFTPClient, str) -> None
    try:
        attr = sftp.lstat(path)
    except (IOError, OSError):
        return
    if stat.S_ISDIR(attr.st_mode):
        for entry in sftp.listdir_attr(path):
            remove_remote(sftp, path + "/" + entry.filename)
        sftp.rmdir(path)
    else:
        sftp.remove(path)


def sync_tree(sftp, local_root, remote_root, direction, dry_run, changes):
    # type: (paramiko.SFTPClient, str, str, str, bool, List[Change]) -> None
    sync_dir(sftp, local_root, remote_root, "", direction, dry_run, changes)


def sync_dir(sftp, local_dir, remote_dir, rel, direction, dry_run, changes):
    # type: (paramiko.SFTPClient, str, str, str, str, bool, List[Change]) -> None
    local_entries = list_local_entries(local_dir)
    remote_entries = list_remote_entries(sftp, remote_dir)
    if direction == "push":
        source_entries = local_entries
        dest_entries = remote_entries
    else:
        source_entries = remote_entries
        dest_entries = local_entries

    names = set(local_entries.keys()) | set(remote_entries.keys())
    for name in sorted(names):
        child_rel = name if rel == "" else rel + "/" + name
        local_kind = local_entries.get(name)
        remote_kind = remote_entries.get(name)
        source_kind = source_entries.get(name)
        dest_kind = dest_entries.get(name)
        local_path = os.path.join(local_dir, name)
        remote_path = remote_dir + "/" + name

        if source_kind is not None and dest_kind is None:
            create_entry(
                sftp, local_path, remote_path, child_rel, source_kind,
                direction, dry_run, changes,
            )
        elif source_kind is None and dest_kind is not None:
            delete_entry(
                sftp, local_path, remote_path, child_rel, dest_kind,
                direction, dry_run, changes,
            )
        elif source_kind == "dir" and dest_kind == "dir":
            sync_dir(
                sftp, local_path, remote_path, child_rel,
                direction, dry_run, changes,
            )
        elif source_kind == "file" and dest_kind == "file":
            if files_differ(sftp, local_path, remote_path):
                overwrite_entry(
                    sftp, local_path, remote_path, child_rel,
                    direction, dry_run, changes,
                )
        else:
            delete_entry(
                sftp, local_path, remote_path, child_rel, dest_kind,
                direction, dry_run, changes,
            )
            create_entry(
                sftp, local_path, remote_path, child_rel, source_kind,
                direction, dry_run, changes,
            )


def create_entry(sftp, local_path, remote_path, rel, kind, direction, dry_run, changes):
    # type: (paramiko.SFTPClient, str, str, str, str, str, bool, List[Change]) -> None
    if kind == "dir":
        changes.append(MkdirChange(rel + "/"))
        if dry_run:
            return
        if direction == "push":
            sftp.mkdir(remote_path)
        else:
            os.mkdir(local_path)
        sync_dir(
            sftp, local_path, remote_path, rel, direction, dry_run, changes
        )
        return

    changes.append(AddChange(rel))
    if dry_run:
        return
    if direction == "push":
        sftp.put(local_path, remote_path)
    else:
        sftp.get(remote_path, local_path)


def overwrite_entry(sftp, local_path, remote_path, rel, direction, dry_run, changes):
    # type: (paramiko.SFTPClient, str, str, str, str, bool, List[Change]) -> None
    changes.append(UpdateChange(rel))
    if dry_run:
        return
    if direction == "push":
        sftp.put(local_path, remote_path)
    else:
        sftp.get(remote_path, local_path)


def delete_entry(sftp, local_path, remote_path, rel, kind, direction, dry_run, changes):
    # type: (paramiko.SFTPClient, str, str, str, str, str, bool, List[Change]) -> None
    suffix = "/" if kind == "dir" else ""
    changes.append(DeleteChange(rel + suffix))
    if dry_run:
        return
    if direction == "push":
        remove_remote(sftp, remote_path)
    else:
        remove_local(local_path)


def print_changes(title, changes):
    # type: (str, List[Change]) -> None
    print(title)
    if not changes:
        print("  (no changes)")
        return
    for change in changes:
        print("  %s %s" % (change.verb, change.rel))


def command_init(name, host, port, username, auth, fingerprint):
    # type: (str, str, int, str, Auth, str) -> int
    validate_namespace_name(name)
    if os.path.exists(name):
        raise KeeplockError('local path "%s" already exists' % (name,))

    transport, sftp = connect_sftp(host, port, username, auth)
    try:
        owner = find_namespace_owner(sftp, name)
        if owner is not None:
            if owner == fingerprint:
                raise KeeplockError(
                    'namespace "%s" already exists.' % (name,)
                )
            raise KeeplockError(
                '"%s" is already owned by a different terminal.' % (name,)
            )
        ensure_remote_dir(sftp, identity_dir_path(fingerprint))
        sftp.mkdir(namespace_remote_path(fingerprint, name))
    finally:
        close_connection(transport, sftp)

    os.mkdir(name)
    write_local_config(
        os.path.join(name, LOCAL_CONFIG_FILENAME), host, port, username
    )
    print(
        'Creating namespace "%s" (bound to this Keeplock identity key)... done'
        % (name,)
    )
    print('Mirroring namespace into ./%s... done' % (name,))
    return 0


def command_ls(host, port, username, auth, fingerprint):
    # type: (str, int, str, Auth, str) -> int
    transport, sftp = connect_sftp(host, port, username, auth)
    try:
        namespaces = scan_namespaces(sftp)
    finally:
        close_connection(transport, sftp)

    writable = []  # type: List[str]
    read_only = []  # type: List[str]
    for namespace, owners in namespaces.items():
        if fingerprint in owners:
            writable.append(namespace)
        else:
            read_only.append(namespace)
    writable.sort()
    read_only.sort()

    for namespace in writable:
        print("write:      %s" % (namespace,))
    for namespace in read_only:
        print("read-only:  %s" % (namespace,))
    return 0


def command_push(auth, fingerprint, dry_run):
    # type: (Auth, str, bool) -> int
    host, port, username = read_local_config(os.getcwd())
    namespace = os.path.basename(os.getcwd())
    validate_namespace_name(namespace)

    transport, sftp = connect_sftp(host, port, username, auth)
    changes = []  # type: List[Change]
    try:
        owner = find_namespace_owner(sftp, namespace)
        if owner != fingerprint:
            raise KeeplockError(
                'this Keeplock identity key does not own namespace "%s".'
                % (namespace,)
            )
        print(
            'Verifying this Keeplock identity key owns "%s"... ok' % (namespace,)
        )
        remote_root = namespace_remote_path(fingerprint, namespace)
        sync_tree(
            sftp, os.getcwd(), remote_root, "push", dry_run, changes
        )
    finally:
        close_connection(transport, sftp)

    if dry_run:
        print_changes(
            "Dry-run: the following changes would be made to the server tree:",
            changes,
        )
    else:
        print("Mirroring server tree to match local... done")
        print("remote: tree updated")
    return 0


def command_clone(name, host, port, username, auth, fingerprint):
    # type: (str, str, int, str, Auth, str) -> int
    validate_namespace_name(name)
    if os.path.exists(name):
        raise KeeplockError('local path "%s" already exists' % (name,))

    transport, sftp = connect_sftp(host, port, username, auth)
    owner = None  # type: Optional[str]
    try:
        owner = find_namespace_owner(sftp, name)
        if owner is None:
            raise KeeplockError(
                'namespace "%s" does not exist on the server.' % (name,)
            )
        remote_root = namespace_remote_path(owner, name)
        os.mkdir(name)
        changes = []  # type: List[Change]
        sync_tree(
            sftp, os.path.abspath(name), remote_root, "pull", False, changes
        )
    finally:
        close_connection(transport, sftp)

    write_local_config(
        os.path.join(name, LOCAL_CONFIG_FILENAME), host, port, username
    )
    if owner == fingerprint:
        print('Cloning namespace "%s" into ./%s... done' % (name, name))
    else:
        print(
            'Cloning read-only mirror of "%s" into ./%s... done'
            % (name, name)
        )
    return 0


def command_pull(auth, dry_run):
    # type: (Auth, bool) -> int
    host, port, username = read_local_config(os.getcwd())
    namespace = os.path.basename(os.getcwd())
    validate_namespace_name(namespace)

    transport, sftp = connect_sftp(host, port, username, auth)
    changes = []  # type: List[Change]
    try:
        owner = find_namespace_owner(sftp, namespace)
        if owner is None:
            raise KeeplockError(
                'namespace "%s" does not exist on the server.' % (namespace,)
            )
        remote_root = namespace_remote_path(owner, namespace)
        sync_tree(
            sftp, os.getcwd(), remote_root, "pull", dry_run, changes
        )
    finally:
        close_connection(transport, sftp)

    if dry_run:
        print_changes(
            "Dry-run: the following changes would be made to the local tree:",
            changes,
        )
    else:
        print("Downloading current server tree... done")
    return 0


def parse_args():
    # type: () -> argparse.Namespace
    parser = argparse.ArgumentParser(
        prog="keeplock",
        description="Deliberate hand-offs for developers who work across devices.",
    )
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser(
        "init",
        help="create a namespace and bind it to this Keeplock identity key",
    )
    init_parser.add_argument(
        "name", help="namespace name (also the local directory name)"
    )
    init_parser.add_argument(
        "--host", required=True, help="SSH server host name or address"
    )
    init_parser.add_argument(
        "--port",
        type=int,
        default=22,
        help="SSH server port number (default: 22)",
    )
    init_parser.add_argument(
        "--username", required=True, help="SSH server username"
    )
    init_server_auth = init_parser.add_mutually_exclusive_group(required=True)
    init_server_auth.add_argument(
        "--ed25519-key",
        help="user-facing path to the Ed25519 private key used to access the SSH server",
    )
    init_server_auth.add_argument(
        "--rsa-key",
        help="user-facing path to the RSA private key used to access the SSH server",
    )
    init_server_auth.add_argument(
        "--password",
        help="password used to connect to the remote SSH server",
    )
    init_identity = init_parser.add_mutually_exclusive_group(required=False)
    init_identity.add_argument(
        "--identity-ed25519-key",
        help="user-facing path to the Ed25519 Keeplock identity key",
    )
    init_identity.add_argument(
        "--identity-rsa-key",
        help="user-facing path to the RSA Keeplock identity key",
    )

    ls_parser = subparsers.add_parser(
        "ls", help="list namespaces visible to this Keeplock identity key"
    )
    ls_parser.add_argument(
        "--host", required=True, help="SSH server host name or address"
    )
    ls_parser.add_argument(
        "--port",
        type=int,
        default=22,
        help="SSH server port number (default: 22)",
    )
    ls_parser.add_argument(
        "--username", required=True, help="SSH server username"
    )
    ls_server_auth = ls_parser.add_mutually_exclusive_group(required=True)
    ls_server_auth.add_argument(
        "--ed25519-key",
        help="user-facing path to the Ed25519 private key used to access the SSH server",
    )
    ls_server_auth.add_argument(
        "--rsa-key",
        help="user-facing path to the RSA private key used to access the SSH server",
    )
    ls_server_auth.add_argument(
        "--password",
        help="password used to connect to the remote SSH server",
    )
    ls_identity = ls_parser.add_mutually_exclusive_group(required=False)
    ls_identity.add_argument(
        "--identity-ed25519-key",
        help="user-facing path to the Ed25519 Keeplock identity key",
    )
    ls_identity.add_argument(
        "--identity-rsa-key",
        help="user-facing path to the RSA Keeplock identity key",
    )

    clone_parser = subparsers.add_parser(
        "clone", help="clone a namespace as a local mirror"
    )
    clone_parser.add_argument(
        "name", help="namespace name (also the local directory name)"
    )
    clone_parser.add_argument(
        "--host", required=True, help="SSH server host name or address"
    )
    clone_parser.add_argument(
        "--port",
        type=int,
        default=22,
        help="SSH server port number (default: 22)",
    )
    clone_parser.add_argument(
        "--username", required=True, help="SSH server username"
    )
    clone_server_auth = clone_parser.add_mutually_exclusive_group(required=True)
    clone_server_auth.add_argument(
        "--ed25519-key",
        help="user-facing path to the Ed25519 private key used to access the SSH server",
    )
    clone_server_auth.add_argument(
        "--rsa-key",
        help="user-facing path to the RSA private key used to access the SSH server",
    )
    clone_server_auth.add_argument(
        "--password",
        help="password used to connect to the remote SSH server",
    )
    clone_identity = clone_parser.add_mutually_exclusive_group(required=False)
    clone_identity.add_argument(
        "--identity-ed25519-key",
        help="user-facing path to the Ed25519 Keeplock identity key",
    )
    clone_identity.add_argument(
        "--identity-rsa-key",
        help="user-facing path to the RSA Keeplock identity key",
    )

    push_parser = subparsers.add_parser(
        "push", help="publish the current local tree to the server"
    )
    push_parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="report the changes that would be made without making them",
    )
    push_server_auth = push_parser.add_mutually_exclusive_group(required=True)
    push_server_auth.add_argument(
        "--ed25519-key",
        help="user-facing path to the Ed25519 private key used to access the SSH server",
    )
    push_server_auth.add_argument(
        "--rsa-key",
        help="user-facing path to the RSA private key used to access the SSH server",
    )
    push_server_auth.add_argument(
        "--password",
        help="password used to connect to the remote SSH server",
    )
    push_identity = push_parser.add_mutually_exclusive_group(required=False)
    push_identity.add_argument(
        "--identity-ed25519-key",
        help="user-facing path to the Ed25519 Keeplock identity key",
    )
    push_identity.add_argument(
        "--identity-rsa-key",
        help="user-facing path to the RSA Keeplock identity key",
    )

    pull_parser = subparsers.add_parser(
        "pull", help="update the current local mirror from the server"
    )
    pull_parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="report the changes that would be made without making them",
    )
    pull_server_auth = pull_parser.add_mutually_exclusive_group(required=True)
    pull_server_auth.add_argument(
        "--ed25519-key",
        help="user-facing path to the Ed25519 private key used to access the SSH server",
    )
    pull_server_auth.add_argument(
        "--rsa-key",
        help="user-facing path to the RSA private key used to access the SSH server",
    )
    pull_server_auth.add_argument(
        "--password",
        help="password used to connect to the remote SSH server",
    )
    pull_identity = pull_parser.add_mutually_exclusive_group(required=False)
    pull_identity.add_argument(
        "--identity-ed25519-key",
        help="user-facing path to the Ed25519 Keeplock identity key",
    )
    pull_identity.add_argument(
        "--identity-rsa-key",
        help="user-facing path to the RSA Keeplock identity key",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(2)

    return args


def main():
    # type: () -> int
    args = parse_args()
    try:
        if args.command == "init":
            fingerprint = identity_fingerprint(load_identity_key(args))
            host, port, username = server_connection_from_args(args)
            return command_init(
                args.name, host, port, username, load_server_auth(args), fingerprint
            )
        if args.command == "ls":
            fingerprint = identity_fingerprint(load_identity_key(args))
            host, port, username = server_connection_from_args(args)
            return command_ls(
                host, port, username, load_server_auth(args), fingerprint
            )
        if args.command == "clone":
            fingerprint = identity_fingerprint(load_identity_key(args))
            host, port, username = server_connection_from_args(args)
            return command_clone(
                args.name, host, port, username, load_server_auth(args), fingerprint
            )
        if args.command == "push":
            fingerprint = identity_fingerprint(load_identity_key(args))
            return command_push(load_server_auth(args), fingerprint, args.dry_run)
        if args.command == "pull":
            return command_pull(load_server_auth(args), args.dry_run)
        raise KeeplockError("unknown command: %s" % (args.command,))
    except KeeplockError as error:
        print("error: %s" % (error,), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
