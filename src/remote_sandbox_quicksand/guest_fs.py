"""Codex filesystem operations. Only the guest agent inside the VM instantiates this class.

The URI helpers are lexical and safe to import on the host. All filesystem I/O
is deliberately confined to FileSystemSession and its private helpers.
"""

import base64
import binascii
from contextlib import contextmanager
import errno
import os
import posixpath
import re
import stat
from urllib.parse import quote, unquote, urlsplit

FILE_BYTES = 8 * 1024 * 1024
SNAPSHOT_BYTES = 32 * 1024 * 1024
MAX_HANDLES = 64
MAX_ENTRIES = 10000
MAX_INTEGER = 2**53 - 1
METHODS = {
    "fs/readFile", "fs/open", "fs/readBlock", "fs/close", "fs/writeFile",
    "fs/createDirectory", "fs/getMetadata", "fs/canonicalize", "fs/readDirectory",
    "fs/walk", "fs/remove", "fs/copy",
}


def fail(code, message=None):
    error = OSError(getattr(errno, code), message or code)
    error.code = code
    raise error


def integer(value, maximum=MAX_INTEGER):
    if type(value) is not int or not 0 <= value <= maximum:
        fail("EINVAL")
    return value


def boolean(value, default):
    if value is None:
        return default
    if type(value) is not bool:
        fail("EINVAL")
    return value


def guest_path(value):
    if (not isinstance(value, str) or not value.startswith("/")
            or re.search(r"[\x00-\x1f\x7f]", value)
            or len(value.encode("utf-8")) > 4096):
        fail("EINVAL", "Expected an absolute guest path")
    return "/" + posixpath.normpath(value).lstrip("/")


def guest_path_from_uri(value):
    if (not isinstance(value, str) or not re.match(r"^file://(?:localhost)?/", value)
            or re.search(r"[\x00-\x1f\x7f\\]", value)):
        fail("EINVAL", "Expected a local file:// guest URI")
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "file" or parsed.netloc not in ("", "localhost")
                or parsed.query or parsed.fragment or "?" in value or "#" in value
                or re.search(r"%2f", parsed.path, re.I)
                or re.search(r"%(?![0-9a-fA-F]{2})", parsed.path)):
            fail("EINVAL")
        return guest_path(unquote(parsed.path, errors="strict"))
    except (ValueError, UnicodeError):
        fail("EINVAL", "Invalid guest file URI")


def guest_path_to_uri(value):
    return "file://" + quote(guest_path(value), safe="/!~*'()")


def decode(value, maximum=FILE_BYTES):
    if not isinstance(value, str):
        fail("EINVAL")
    if len(value) > ((maximum + 2) // 3) * 4:
        fail("EFBIG")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        fail("EINVAL", "Invalid base64")
    if len(data) > maximum:
        fail("EFBIG")
    if base64.b64encode(data).decode("ascii") != value:
        fail("EINVAL", "Noncanonical base64")
    return data


def handle_id(value):
    if not isinstance(value, str) or "\0" in value or len(value.encode()) > 32:
        fail("EINVAL")
    return value


def kind(mode):
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


@contextmanager
def parent_path(path, follow=True, create=False, mode=0o755):
    """For no-follow operations, pin every ancestor with an open directory fd."""
    if follow:
        yield None, path
        return
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    pieces = path.strip("/").split("/") if path != "/" else ["."]
    try:
        for piece in pieces[:-1]:
            try:
                child = os.open(piece, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(piece, mode, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(piece, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor, pieces[-1]
    finally:
        os.close(descriptor)


def metadata(path, follow=True):
    with parent_path(path, follow) as (parent, leaf):
        return os.stat(leaf, dir_fd=parent, follow_symlinks=follow)


def read_file(path, follow=True):
    with parent_path(path, follow) as (parent, leaf):
        info = os.stat(leaf, dir_fd=parent, follow_symlinks=follow)
        if stat.S_ISLNK(info.st_mode):
            fail("ELOOP")
        if not stat.S_ISREG(info.st_mode):
            fail("EISDIR")
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        if not follow:
            flags |= os.O_NOFOLLOW
        fd = os.open(leaf, flags, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                fail("EISDIR")
            if info.st_size > FILE_BYTES:
                fail("EFBIG")
            chunks, size = [], 0
            while True:
                chunk = os.read(fd, min(49152, FILE_BYTES + 1 - size))
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
                size += len(chunk)
                if size > FILE_BYTES:
                    fail("EFBIG")
        finally:
            os.close(fd)


def write_file(path, data, follow=True, mode=0o644, restore_mode=None):
    with parent_path(path, follow) as (parent, leaf):
        flags = os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC | os.O_NONBLOCK
        if not follow:
            flags |= os.O_NOFOLLOW
        fd = os.open(leaf, flags, mode, dir_fd=parent)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                fail("EINVAL", "Can only write regular files")
            os.ftruncate(fd, 0)
            offset = 0
            while offset < len(data):
                written = os.write(fd, data[offset:offset + 49152])
                if not written:
                    fail("EIO")
                offset += written
            if restore_mode is not None:
                os.fchmod(fd, restore_mode)
        finally:
            os.close(fd)


def directory_entries(path, follow=True):
    with parent_path(path, follow) as (parent, leaf):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        if not follow:
            flags |= os.O_NOFOLLOW
        fd = os.open(leaf, flags, dir_fd=parent)
        try:
            result = []
            with os.scandir(fd) as listing:
                for entry in listing:
                    if len(result) >= MAX_ENTRIES:
                        fail("EFBIG")
                    if re.search(r"[\x00-\x1f\x7f]", entry.name):
                        fail("EIO", "Invalid directory entry")
                    try:
                        entry.name.encode("utf-8")
                    except UnicodeError:
                        fail("EILSEQ")
                    result.append((entry.name, kind(entry.stat(follow_symlinks=False).st_mode)))
            return result
        finally:
            os.close(fd)


def create_directory(path, recursive, follow, mode=0o755):
    if follow and recursive:
        os.makedirs(path, mode=mode, exist_ok=True)
        return
    with parent_path(path, follow, recursive, mode) as (parent, leaf):
        try:
            os.mkdir(leaf, mode, dir_fd=parent)
        except FileExistsError:
            if not recursive:
                raise
            if not stat.S_ISDIR(os.stat(leaf, dir_fd=parent, follow_symlinks=follow).st_mode):
                fail("ENOTDIR")


def remove_at(parent, name, recursive, depth=0):
    if depth > 64:
        fail("ELOOP")
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        os.unlink(name, dir_fd=parent)
        return
    if recursive:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            with os.scandir(fd) as listing:
                for entry in listing:
                    remove_at(fd, entry.name, True, depth + 1)
        finally:
            os.close(fd)
    os.rmdir(name, dir_fd=parent)


class FileSystemSession:
    """Bounded immutable read snapshots and guest-local Codex filesystem methods."""

    def __init__(self):
        self.snapshots = {}
        self.snapshot_bytes = 0
        self.closed = False

    def close(self):
        self.closed = True
        self.snapshots.clear()
        self.snapshot_bytes = 0

    def handle(self, method, params):
        if self.closed:
            fail("ECANCELED")
        if method not in METHODS:
            fail("ENOSYS")
        if not isinstance(params, dict):
            fail("EINVAL")
        if params.get("sandbox") is not None:
            fail("ENOTSUP", "Authorize sandbox context before filesystem dispatch")
        if method == "fs/readBlock":
            data = self.snapshots.get(handle_id(params.get("handleId")))
            if data is None:
                fail("EBADF")
            offset = integer(params.get("offset"))
            length = integer(params.get("len"), FILE_BYTES)
            end = min(len(data), offset + length)
            return {"chunk": base64.b64encode(data[offset:end]).decode(), "eof": end >= len(data)}
        if method == "fs/close":
            data = self.snapshots.pop(handle_id(params.get("handleId")), None)
            if data is not None:
                self.snapshot_bytes -= len(data)
            return {}
        if method == "fs/copy":
            if type(params.get("recursive")) is not bool:
                fail("EINVAL")
            self._copy(guest_path_from_uri(params.get("sourcePath")),
                       guest_path_from_uri(params.get("destinationPath")), params["recursive"])
            return {}
        path = guest_path_from_uri(params.get("path"))
        follow = boolean(params.get("followSymlinks"), True)
        if method == "fs/readFile":
            return {"dataBase64": base64.b64encode(read_file(path, follow)).decode()}
        if method == "fs/writeFile":
            write_file(path, decode(params.get("dataBase64")), follow)
            return {}
        if method == "fs/open":
            identifier = handle_id(params.get("handleId"))
            if identifier in self.snapshots:
                fail("EEXIST")
            if len(self.snapshots) >= MAX_HANDLES:
                fail("EMFILE")
            data = read_file(path)
            if self.snapshot_bytes + len(data) > SNAPSHOT_BYTES:
                fail("ENOMEM")
            self.snapshots[identifier] = data
            self.snapshot_bytes += len(data)
            return {"handleId": identifier}
        if method == "fs/getMetadata":
            info = metadata(path, follow)
            return {"isDirectory": stat.S_ISDIR(info.st_mode), "isFile": stat.S_ISREG(info.st_mode),
                    "isSymlink": stat.S_ISLNK(info.st_mode), "size": info.st_size,
                    "createdAtMs": 0, "modifiedAtMs": int(info.st_mtime) * 1000}
        if method == "fs/canonicalize":
            return {"path": guest_path_to_uri(os.path.realpath(path, strict=True))}
        if method == "fs/readDirectory":
            return {"entries": [{"fileName": name, "isDirectory": type_ == "directory", "isFile": type_ == "file"}
                                for name, type_ in directory_entries(path)]}
        if method == "fs/createDirectory":
            create_directory(path, boolean(params.get("recursive"), True), follow)
            return {}
        if method == "fs/remove":
            force = boolean(params.get("force"), True)
            recursive = boolean(params.get("recursive"), True)
            if path == "/":
                fail("EPERM")
            try:
                with parent_path(path, follow) as (parent, leaf):
                    remove_at(parent, leaf, recursive)
            except FileNotFoundError:
                if not force:
                    raise
            return {}
        if method == "fs/walk":
            return self._walk(path, params.get("options"))
        fail("ENOSYS")

    def _walk(self, root, options):
        if not isinstance(options, dict):
            fail("EINVAL")
        max_depth = min(integer(options.get("maxDepth")), 64)
        max_directories = min(integer(options.get("maxDirectories")), 4096)
        max_entries = min(integer(options.get("maxEntries")), MAX_ENTRIES)
        follow = boolean(options.get("followDirectorySymlinks"), False)
        prune = boolean(options.get("pruneHiddenDirectories"), False)
        outcome = {"entries": [], "errors": [], "truncated": False}
        visited, examined = set(), 0

        def visit(directory, depth):
            nonlocal examined
            resolved = os.path.realpath(directory, strict=True)
            if resolved in visited:
                return
            if len(visited) >= max_directories:
                outcome["truncated"] = True
                return
            visited.add(resolved)
            for name, type_ in directory_entries(directory):
                if examined >= max_entries:
                    outcome["truncated"] = True
                    return
                examined += 1
                child = posixpath.join(directory, name)
                try:
                    if type_ == "symlink":
                        if not follow:
                            continue
                        type_ = kind(metadata(child).st_mode)
                    if type_ not in ("file", "directory"):
                        continue
                    outcome["entries"].append({"path": guest_path_to_uri(child), "kind": type_})
                    if type_ == "directory" and not (prune and name.startswith(".")):
                        if depth >= max_depth:
                            outcome["truncated"] = True
                        else:
                            visit(child, depth + 1)
                except OSError as error:
                    outcome["errors"].append({"path": guest_path_to_uri(child), "message": str(error)})

        if not stat.S_ISDIR(metadata(root).st_mode):
            fail("ENOTDIR")
        visit(root, 0)
        return outcome

    def _copy(self, source, destination, recursive):
        if source == destination or destination.startswith(source.rstrip("/") + "/"):
            fail("EINVAL", "Cannot copy a path into itself")
        copied, count = 0, 0

        def visit(from_, to, depth):
            nonlocal copied, count
            count += 1
            if depth > 64 or count > MAX_ENTRIES:
                fail("EFBIG")
            info = metadata(from_, False)
            type_ = kind(info.st_mode)
            mode = stat.S_IMODE(info.st_mode) & 0o777
            if type_ in ("symlink", "other"):
                fail("ENOTSUP", "Copying symlinks and special files is unsupported")
            if type_ == "file":
                data = read_file(from_, False)
                copied += len(data)
                if copied > 64 * 1024 * 1024:
                    fail("EFBIG")
                write_file(to, data, False, mode | 0o200, mode)
                return
            if not recursive:
                fail("EISDIR")
            children = directory_entries(from_, False)
            create_directory(to, True, False, mode | 0o700)
            for name, _ in children:
                visit(posixpath.join(from_, name), posixpath.join(to, name), depth + 1)
            with parent_path(to, False) as (parent, leaf):
                fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    os.fchmod(fd, mode)
                finally:
                    os.close(fd)

        visit(source, destination, 0)
