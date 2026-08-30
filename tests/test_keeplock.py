#!/usr/bin/env python
# Copyright (c) 2026 Jifeng Wu
# Licensed under the MIT License. See LICENSE file in the project root for full license information.
"""Unit tests for Keeplock helpers, change records, and argument parsing."""

import hashlib
import os
import shutil
import sys
import tempfile
import unittest

import keeplock


class OutputCapture(object):
    __slots__ = ("text",)

    def __init__(self):
        # type: () -> None
        self.text = ""  # type: str

    def write(self, chunk):
        # type: (str) -> None
        self.text = self.text + chunk


class FakeKey(object):
    __slots__ = ("blob",)

    def __init__(self, blob):
        # type: (bytes) -> None
        self.blob = blob  # type: bytes

    def asbytes(self):
        # type: () -> bytes
        return self.blob


class ChangeTest(unittest.TestCase):
    def test_verbs(self):
        self.assertEqual(keeplock.AddChange("a").verb, "add")
        self.assertEqual(keeplock.UpdateChange("a").verb, "update")
        self.assertEqual(keeplock.DeleteChange("a").verb, "delete")
        self.assertEqual(keeplock.MkdirChange("a/").verb, "mkdir")

    def test_rel(self):
        self.assertEqual(keeplock.AddChange("dir/file.txt").rel, "dir/file.txt")

    def test_print_changes(self):
        changes = [
            keeplock.MkdirChange("sub/"),
            keeplock.AddChange("a.txt"),
            keeplock.UpdateChange("b.txt"),
            keeplock.DeleteChange("c.txt"),
        ]
        capture = OutputCapture()
        old_stdout = sys.stdout
        sys.stdout = capture
        try:
            keeplock.print_changes("Dry-run:", changes)
        finally:
            sys.stdout = old_stdout

        self.assertIn("mkdir", capture.text)
        self.assertIn("add", capture.text)
        self.assertIn("update", capture.text)
        self.assertIn("delete", capture.text)
        self.assertIn("a.txt", capture.text)
        self.assertIn("c.txt", capture.text)

    def test_print_changes_empty(self):
        capture = OutputCapture()
        old_stdout = sys.stdout
        sys.stdout = capture
        try:
            keeplock.print_changes("Dry-run:", [])
        finally:
            sys.stdout = old_stdout
        self.assertIn("(no changes)", capture.text)


class ValidateNamespaceNameTest(unittest.TestCase):
    def test_valid(self):
        keeplock.validate_namespace_name("phone")
        keeplock.validate_namespace_name("my-namespace")

    def test_empty(self):
        with self.assertRaises(keeplock.KeeplockError):
            keeplock.validate_namespace_name("")

    def test_dots(self):
        with self.assertRaises(keeplock.KeeplockError):
            keeplock.validate_namespace_name(".")
        with self.assertRaises(keeplock.KeeplockError):
            keeplock.validate_namespace_name("..")

    def test_separators(self):
        with self.assertRaises(keeplock.KeeplockError):
            keeplock.validate_namespace_name("a/b")
        with self.assertRaises(keeplock.KeeplockError):
            keeplock.validate_namespace_name("a\\b")


class PathHelperTest(unittest.TestCase):
    def test_identity_dir_path(self):
        self.assertEqual(
            keeplock.identity_dir_path("sha256-abc"), ".keeplock/sha256-abc"
        )

    def test_namespace_remote_path(self):
        self.assertEqual(
            keeplock.namespace_remote_path("sha256-abc", "phone"),
            ".keeplock/sha256-abc/phone",
        )


class IdentityFingerprintTest(unittest.TestCase):
    def test_format(self):
        blob = b"ssh-ed25519" + b"\x00" * 16
        fingerprint = keeplock.identity_fingerprint(FakeKey(blob))
        expected = "sha256-" + hashlib.sha256(blob).hexdigest()
        self.assertEqual(fingerprint, expected)
        self.assertTrue(fingerprint.startswith("sha256-"))
        self.assertEqual(len(fingerprint), len("sha256-") + 64)


class LocalConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_round_trip(self):
        path = os.path.join(self.tmp, keeplock.LOCAL_CONFIG_FILENAME)
        keeplock.write_local_config(path, "example.com", 2222, "user")
        self.assertEqual(
            keeplock.read_local_config(self.tmp),
            ("example.com", 2222, "user"),
        )

    def test_missing(self):
        with self.assertRaises(keeplock.KeeplockError):
            keeplock.read_local_config(self.tmp)

    def test_invalid_json(self):
        path = os.path.join(self.tmp, keeplock.LOCAL_CONFIG_FILENAME)
        with open(path, "w") as stream:
            stream.write("{not json")
        with self.assertRaises(keeplock.KeeplockError):
            keeplock.read_local_config(self.tmp)


class ParseArgsTest(unittest.TestCase):
    def parse_with_argv(self, argv):
        old_argv = sys.argv
        sys.argv = argv
        try:
            return keeplock.parse_args()
        finally:
            sys.argv = old_argv

    def test_init(self):
        args = self.parse_with_argv(
            [
                "keeplock",
                "init",
                "phone",
                "--host",
                "example.com",
                "--port",
                "2222",
                "--username",
                "user",
                "--password",
                "secret",
            ]
        )
        self.assertEqual(args.command, "init")
        self.assertEqual(args.name, "phone")
        self.assertEqual(args.host, "example.com")
        self.assertEqual(args.port, 2222)
        self.assertEqual(args.username, "user")
        self.assertEqual(args.password, "secret")

    def test_ls_default_port(self):
        args = self.parse_with_argv(
            [
                "keeplock",
                "ls",
                "--host",
                "h",
                "--username",
                "u",
                "--password",
                "secret",
            ]
        )
        self.assertEqual(args.command, "ls")
        self.assertEqual(args.port, 22)

    def test_push_dry_run(self):
        args = self.parse_with_argv(
            ["keeplock", "push", "-d", "--ed25519-key", "k"]
        )
        self.assertEqual(args.command, "push")
        self.assertTrue(args.dry_run)
        self.assertEqual(args.ed25519_key, "k")

    def test_clone(self):
        args = self.parse_with_argv(
            [
                "keeplock",
                "clone",
                "phone",
                "--host",
                "h",
                "--username",
                "u",
                "--rsa-key",
                "r",
            ]
        )
        self.assertEqual(args.command, "clone")
        self.assertEqual(args.name, "phone")
        self.assertEqual(args.rsa_key, "r")

    def test_no_command(self):
        with self.assertRaises(SystemExit):
            self.parse_with_argv(["keeplock"])

    def test_init_requires_auth(self):
        with self.assertRaises(SystemExit):
            self.parse_with_argv(
                ["keeplock", "init", "phone", "--host", "h", "--username", "u"]
            )


if __name__ == "__main__":
    unittest.main()
