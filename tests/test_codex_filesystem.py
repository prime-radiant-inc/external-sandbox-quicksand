import base64
import errno
import os
from pathlib import Path
import tempfile
import unittest

from remote_sandbox_quicksand.guest_fs import FILE_BYTES, FileSystemSession, guest_path_from_uri, guest_path_to_uri


class FileSystemTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.fs = FileSystemSession()
        self.file = self.root / "file"
        self.file.write_bytes(bytes([0, 255, 1, 2]))

    def tearDown(self):
        self.fs.close()
        for path in self.root.rglob("*"):
            if not path.is_symlink():
                path.chmod(0o700 if path.is_dir() else 0o600)
        self.temporary.cleanup()

    def call(self, method, path=None, **params):
        if path is not None:
            params["path"] = guest_path_to_uri(str(path))
        return self.fs.handle(method, params)

    def test_uri_validation_is_lexical(self):
        self.assertEqual(guest_path_from_uri("file://localhost/work/a%20b%23%25.txt"), "/work/a b#%.txt")
        self.assertEqual(guest_path_to_uri("/work/a b#%.txt"), "file:///work/a%20b%23%25.txt")
        for value in ["relative", "/work/file", "file:/work/file", "file://remote/work/file", "file://user@localhost/work/file",
                      "file:///work/file?x=1", "file:///work/file#fragment", "file:///work/%00", "file:///work/%2fetc", "file:///work/%zz"]:
            with self.assertRaises(OSError):
                guest_path_from_uri(value)

    def test_binary_and_full_file_boundary(self):
        data = bytes(range(256)) * (FILE_BYTES // 256)
        encoded = base64.b64encode(data).decode()
        self.call("fs/writeFile", self.file, dataBase64=encoded, followSymlinks=False)
        self.assertEqual(self.call("fs/readFile", self.file), {"dataBase64": encoded})
        self.call("fs/writeFile", self.file, dataBase64="")
        self.assertEqual(self.file.read_bytes(), b"")
        with self.file.open("wb") as output:
            output.truncate(FILE_BYTES + 1)
        with self.assertRaises(OSError) as error:
            self.call("fs/readFile", self.file)
        self.assertEqual(error.exception.errno, errno.EFBIG)

    def test_snapshot_and_handle_limits(self):
        self.assertEqual(self.call("fs/open", self.file, handleId="one"), {"handleId": "one"})
        self.file.write_text("changed")
        self.assertEqual(self.call("fs/readBlock", handleId="one", offset=1, len=2), {"chunk": "/wE=", "eof": False})
        self.assertEqual(self.call("fs/readBlock", handleId="one", offset=100, len=3), {"chunk": "", "eof": True})
        for identifier in ["one", "x" * 33]:
            with self.assertRaises(OSError):
                self.call("fs/open", self.file, handleId=identifier)
        for i in range(63):
            self.call("fs/open", self.file, handleId=f"h{i}")
        with self.assertRaises(OSError) as error:
            self.call("fs/open", self.file, handleId="overflow")
        self.assertEqual(error.exception.errno, errno.EMFILE)
        self.call("fs/close", handleId="one")
        self.call("fs/close", handleId="one")
        with self.assertRaises(OSError):
            self.call("fs/readBlock", handleId="one", offset=0, len=1)

    def test_metadata_directory_and_symlink_policy(self):
        link = self.root / "link"
        link.symlink_to(self.file)
        self.assertTrue(self.call("fs/getMetadata", link)["isFile"])
        self.assertTrue(self.call("fs/getMetadata", link, followSymlinks=False)["isSymlink"])
        self.assertEqual(self.call("fs/canonicalize", link), {"path": guest_path_to_uri(str(self.file))})
        listing = self.call("fs/readDirectory", self.root)["entries"]
        self.assertIn({"fileName": "link", "isDirectory": False, "isFile": False}, listing)
        with self.assertRaises(OSError):
            self.call("fs/writeFile", link, dataBase64="YQ==", followSymlinks=False)
        ancestor = self.root / "ancestor"
        ancestor.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            self.call("fs/readFile", ancestor / "file", followSymlinks=False)

    def test_malformed_data_and_policy_fail_before_mutation(self):
        old = self.file.read_bytes()
        for encoded in ["%%%not-base64", "YQ", "YR==", base64.b64encode(b"x" * (FILE_BYTES + 1)).decode()]:
            with self.assertRaises(OSError):
                self.call("fs/writeFile", self.file, dataBase64=encoded)
        with self.assertRaises(OSError):
            self.call("fs/writeFile", self.file, dataBase64="", sandbox={"arbitrary": True})
        self.assertEqual(self.file.read_bytes(), old)
        with self.assertRaises(OSError):
            self.call("fs/unknown")

    def test_copy_preserves_modes_and_rejects_links_or_self(self):
        tree = self.root / "tree"
        tree.mkdir()
        child = tree / "child"
        child.write_bytes(b"a" * 100000)
        child.chmod(0o400)
        tree.chmod(0o500)
        dest = self.root / "copied"
        self.call("fs/copy", sourcePath=guest_path_to_uri(str(tree)), destinationPath=guest_path_to_uri(str(dest)), recursive=True)
        self.assertEqual((dest / "child").read_bytes(), b"a" * 100000)
        self.assertEqual((dest / "child").stat().st_mode & 0o777, 0o400)
        self.assertEqual(dest.stat().st_mode & 0o777, 0o500)
        for source, target in [(tree, tree / "inner"), (self.file, self.file)]:
            with self.assertRaises(OSError):
                self.call("fs/copy", sourcePath=guest_path_to_uri(str(source)), destinationPath=guest_path_to_uri(str(target)), recursive=True)
        link = self.root / "link"
        link.symlink_to(self.file)
        with self.assertRaises(OSError):
            self.call("fs/copy", sourcePath=guest_path_to_uri(str(link)), destinationPath=guest_path_to_uri(str(self.root / "other")), recursive=False)

    def test_walk_bounds_hidden_pruning_and_cycles(self):
        hidden, sub = self.root / ".hidden", self.root / "sub"
        hidden.mkdir()
        sub.mkdir()
        (hidden / "secret").write_text("x")
        (sub / "child").write_text("x")
        (sub / "back").symlink_to(self.root, target_is_directory=True)
        options = {"maxDepth": 10, "maxDirectories": 10, "maxEntries": 100,
                   "followDirectorySymlinks": True, "pruneHiddenDirectories": True}
        result = self.call("fs/walk", self.root, options=options)
        self.assertFalse(result["truncated"])
        self.assertEqual(result["errors"], [])
        self.assertTrue(any(entry["path"].endswith("/sub/child") for entry in result["entries"]))
        self.assertFalse(any(entry["path"].endswith("/secret") for entry in result["entries"]))
        limited = self.call("fs/walk", self.root, options={**options, "maxEntries": 1})
        self.assertEqual(len(limited["entries"]), 1)
        self.assertTrue(limited["truncated"])

    def test_create_remove_force_and_closed_session(self):
        nested = self.root / "new" / "nested"
        self.call("fs/createDirectory", nested)
        self.assertTrue(nested.is_dir())
        self.call("fs/remove", self.root / "new")
        self.assertFalse(nested.exists())
        self.call("fs/remove", nested)
        with self.assertRaises(FileNotFoundError):
            self.call("fs/remove", nested, force=False)
        self.fs.close()
        with self.assertRaises(OSError) as error:
            self.call("fs/readFile", self.file)
        self.assertEqual(error.exception.errno, errno.ECANCELED)

    def test_remove_directory_symlink_keeps_target(self):
        target = self.root / "target"
        target.mkdir()
        (target / "keep").write_text("safe")
        link = self.root / "link"
        link.symlink_to(target, target_is_directory=True)
        self.call("fs/remove", link, recursive=True)
        self.assertEqual((target / "keep").read_text(), "safe")

    def test_fifo_read_does_not_block(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(OSError):
            self.call("fs/readFile", fifo)
