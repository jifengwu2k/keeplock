#!/usr/bin/env python
# Copyright (c) 2026 Jifeng Wu
# Licensed under the MIT License. See LICENSE file in the project root for full license information.
"""Tests for Keeplock's SFTP tree synchronization engine."""

import hashlib
import os
import shutil
import tempfile
import unittest

from typing import List, Tuple

import keeplock


class FakeEntry(object):
    __slots__ = ("filename", "st_mode", "st_size", "st_mtime", "st_atime")

    def __init__(self, filename, st_mode, st_size, st_mtime=0, st_atime=0):
        # type: (str, int, int, int, int) -> None
        self.filename = filename  # type: str
        self.st_mode = st_mode  # type: int
        self.st_size = st_size  # type: int
        self.st_mtime = st_mtime  # type: int
        self.st_atime = st_atime  # type: int


class FakeSftp(object):
    """A minimal SFTP client facade backed by a real local directory."""

    __slots__ = ("root",)

    def __init__(self, root):
        # type: (str) -> None
        self.root = root  # type: str

    def local_path(self, path):
        # type: (str) -> str
        return os.path.join(self.root, *path.split("/"))

    def stat(self, path):
        # type: (str) -> FakeEntry
        info = os.stat(self.local_path(path))
        return FakeEntry(
            os.path.basename(path),
            info.st_mode,
            info.st_size,
            int(info.st_mtime),
            int(info.st_atime),
        )

    def lstat(self, path):
        # type: (str) -> FakeEntry
        return self.stat(path)

    def listdir_attr(self, path):
        # type: (str) -> List[FakeEntry]
        entries = []  # type: List[FakeEntry]
        for name in sorted(os.listdir(self.local_path(path))):
            info = os.lstat(os.path.join(self.local_path(path), name))
            entries.append(FakeEntry(name, info.st_mode, info.st_size))
        return entries

    def mkdir(self, path):
        # type: (str) -> None
        os.mkdir(self.local_path(path))

    def rmdir(self, path):
        # type: (str) -> None
        os.rmdir(self.local_path(path))

    def remove(self, path):
        # type: (str) -> None
        os.remove(self.local_path(path))

    def open(self, path, mode):
        # type: (str, str) -> object
        return open(self.local_path(path), mode)

    def put(self, local_path, remote_path, callback=None, confirm=True):
        # type: (str, str, object, bool) -> None
        shutil.copyfile(local_path, self.local_path(remote_path))

    def get(self, remote_path, local_path, callback=None):
        # type: (str, str, object) -> None
        shutil.copyfile(self.local_path(remote_path), local_path)

    def utime(self, path, times):
        # type: (str, Tuple[int, int]) -> None
        os.utime(self.local_path(path), times)


class ScanNamespacesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.sftp = FakeSftp(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def make_dir(self, remote_path):
        os.makedirs(self.sftp.local_path(remote_path))

    def test_empty(self):
        self.assertEqual(keeplock.scan_namespaces(self.sftp), {})

    def test_namespaces(self):
        self.make_dir(".keeplock/sha256-a/phone")
        self.make_dir(".keeplock/sha256-b/laptop")
        with open(self.sftp.local_path(".keeplock/README"), "w") as stream:
            stream.write("ignore me")
        self.assertEqual(
            keeplock.scan_namespaces(self.sftp),
            {"phone": ["sha256-a"], "laptop": ["sha256-b"]},
        )

    def test_find_owner(self):
        self.make_dir(".keeplock/sha256-a/phone")
        self.assertEqual(
            keeplock.find_namespace_owner(self.sftp, "phone"), "sha256-a"
        )

    def test_find_owner_missing(self):
        self.assertIsNone(keeplock.find_namespace_owner(self.sftp, "nope"))

    def test_find_owner_multiple(self):
        self.make_dir(".keeplock/sha256-a/phone")
        self.make_dir(".keeplock/sha256-b/phone")
        with self.assertRaises(keeplock.KeeplockError):
            keeplock.find_namespace_owner(self.sftp, "phone")


class SyncTreeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.local_root = os.path.join(self.tmp, "local")
        self.remote_root = os.path.join(self.tmp, "remote")
        os.makedirs(self.local_root)
        os.makedirs(self.remote_root)
        self.sftp = FakeSftp(self.remote_root)
        self.remote_path = keeplock.namespace_remote_path("sha256-x", "phone")
        os.makedirs(self.sftp.local_path(self.remote_path))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def local_file(self, rel):
        return os.path.join(self.local_root, *rel.split("/"))

    def remote_file(self, rel):
        return os.path.join(self.sftp.local_path(self.remote_path), *rel.split("/"))

    def write_local(self, rel, content):
        path = self.local_file(rel)
        parent = os.path.dirname(path)
        if not os.path.isdir(parent):
            os.makedirs(parent)
        with open(path, "w") as stream:
            stream.write(content)

    def read_local(self, rel):
        with open(self.local_file(rel), "r") as stream:
            return stream.read()

    def write_remote(self, rel, content):
        path = self.remote_file(rel)
        parent = os.path.dirname(path)
        if not os.path.isdir(parent):
            os.makedirs(parent)
        with open(path, "w") as stream:
            stream.write(content)

    def read_remote(self, rel):
        with open(self.remote_file(rel), "r") as stream:
            return stream.read()

    def test_push(self):
        self.write_local("hello.txt", "hello\n")
        self.write_local("sub/one.txt", "one\n")
        self.write_remote("old.txt", "old\n")

        changes = []  # type: List[keeplock.Change]
        keeplock.sync_tree(
            self.sftp, self.local_root, self.remote_path, "push", False, changes
        )

        self.assertEqual(self.read_remote("hello.txt"), "hello\n")
        self.assertEqual(self.read_remote("sub/one.txt"), "one\n")
        self.assertFalse(os.path.exists(self.remote_file("old.txt")))

        self.assertEqual(
            sorted([change.verb for change in changes]),
            ["add", "add", "delete", "mkdir"],
        )

    def test_pull(self):
        self.write_remote("a.txt", "remote\n")
        self.write_remote("sub/b.txt", "nested\n")

        changes = []  # type: List[keeplock.Change]
        keeplock.sync_tree(
            self.sftp, self.local_root, self.remote_path, "pull", False, changes
        )

        self.assertEqual(self.read_local("a.txt"), "remote\n")
        self.assertEqual(self.read_local("sub/b.txt"), "nested\n")
        self.assertEqual(
            sorted([change.verb for change in changes]), ["add", "add", "mkdir"]
        )

    def test_dry_run(self):
        self.write_local("new.txt", "new\n")

        changes = []  # type: List[keeplock.Change]
        keeplock.sync_tree(
            self.sftp, self.local_root, self.remote_path, "push", True, changes
        )

        self.assertFalse(os.path.exists(self.remote_file("new.txt")))
        self.assertEqual([change.verb for change in changes], ["add"])

    def test_pull_deletes_local(self):
        self.write_local("extra.txt", "extra\n")

        changes = []  # type: List[keeplock.Change]
        keeplock.sync_tree(
            self.sftp, self.local_root, self.remote_path, "pull", False, changes
        )

        self.assertFalse(os.path.exists(self.local_file("extra.txt")))
        self.assertEqual([change.verb for change in changes], ["delete"])


class RemoteDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.sftp = FakeSftp(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_ensure_remote_dir(self):
        keeplock.ensure_remote_dir(self.sftp, ".keeplock/sha256-x/phone")
        self.assertTrue(
            os.path.isdir(os.path.join(self.tmp, ".keeplock", "sha256-x", "phone"))
        )

    def test_remove_remote(self):
        path = os.path.join(self.tmp, ".keeplock", "sha256-x", "phone")
        os.makedirs(os.path.join(path, "sub"))
        with open(os.path.join(path, "sub", "f.txt"), "w") as stream:
            stream.write("x")
        keeplock.remove_remote(self.sftp, ".keeplock/sha256-x/phone")
        self.assertFalse(os.path.exists(path))


class RemoteEntryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.sftp = FakeSftp(self.tmp)
        self.tree = os.path.join(self.tmp, "tree")
        os.makedirs(os.path.join(self.tree, "sub"))
        with open(os.path.join(self.tree, "a.txt"), "w") as stream:
            stream.write("a")
        with open(os.path.join(self.tree, "sub", "b.txt"), "w") as stream:
            stream.write("b")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_list_remote_entries(self):
        self.assertEqual(
            keeplock.list_remote_entries(self.sftp, "tree"),
            {"a.txt": "file", "sub": "dir"},
        )

    def test_hash_remote_file(self):
        self.assertEqual(
            keeplock.hash_remote_file(self.sftp, "tree/a.txt"),
            hashlib.sha256(b"a").hexdigest(),
        )

    def test_files_differ(self):
        local = os.path.join(self.tmp, "local.txt")
        with open(local, "w") as stream:
            stream.write("a")
        local_stat = os.stat(local)
        os.utime(
            self.sftp.local_path("tree/a.txt"),
            (local_stat.st_atime, local_stat.st_mtime),
        )
        self.assertFalse(keeplock.files_differ(self.sftp, local, "tree/a.txt"))
        with open(local, "w") as stream:
            stream.write("changed")
        self.assertTrue(keeplock.files_differ(self.sftp, local, "tree/a.txt"))


if __name__ == "__main__":
    unittest.main()
