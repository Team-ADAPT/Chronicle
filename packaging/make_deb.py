#!/usr/bin/env python3
"""
Cross-Platform Debian (.deb) Package Builder
Generates standard Debian .deb binary packages on any platform (Linux, macOS)
without requiring dpkg-deb or root privileges.
"""
from __future__ import annotations

import io
import os
import sys
import tarfile
import time
from pathlib import Path


def create_tar_gz(source_dir: Path, exclude_prefix: str = "DEBIAN") -> bytes:
    """Creates an in-memory gzipped tar archive of source_dir with normalized root ownership."""
    buf = io.BytesIO()
    fixed_time = int(time.time())

    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
        for root, dirs, files in os.walk(source_dir):
            rel_root = os.path.relpath(root, source_dir)
            if rel_root == ".":
                rel_parts = []
            else:
                rel_parts = Path(rel_root).parts

            if rel_parts and rel_parts[0] == exclude_prefix:
                continue
            if "__pycache__" in rel_parts:
                continue

            dirs = [d for d in sorted(dirs) if d != "__pycache__"]
            files.sort()

            # Add directory entry
            if rel_root != ".":
                tar_dir_path = "./" + rel_root.replace("\\", "/")
                ti = tarfile.TarInfo(name=tar_dir_path)
                ti.type = tarfile.DIRTYPE
                ti.mtime = fixed_time
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                ti.mode = 0o755
                tar.addfile(ti)

            # Add files and symlinks
            for fname in files:
                if fname == ".DS_Store" or fname.endswith(".py"):
                    continue
                full_path = os.path.join(root, fname)
                rel_file = os.path.relpath(full_path, source_dir)
                tar_file_path = "./" + rel_file.replace("\\", "/")

                lst = os.lstat(full_path)
                ti = tarfile.TarInfo(name=tar_file_path)
                ti.mtime = fixed_time
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"

                if os.path.islink(full_path):
                    ti.type = tarfile.SYMTYPE
                    ti.linkname = os.readlink(full_path)
                    ti.mode = 0o777
                    tar.addfile(ti)
                else:
                    ti.size = lst.st_size
                    if os.access(full_path, os.X_OK):
                        ti.mode = 0o755
                    else:
                        ti.mode = 0o644

                    with open(full_path, "rb") as f:
                        tar.addfile(ti, f)

    return buf.getvalue()


def create_control_tar_gz(debian_dir: Path) -> bytes:
    """Creates control.tar.gz from files inside DEBIAN/."""
    buf = io.BytesIO()
    fixed_time = int(time.time())

    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
        entries = sorted(os.listdir(debian_dir))
        for entry in entries:
            full_path = debian_dir / entry
            if not full_path.is_file():
                continue

            ti = tarfile.TarInfo(name="./" + entry)
            lst = os.lstat(full_path)
            ti.size = lst.st_size
            ti.mtime = fixed_time
            ti.uid = 0
            ti.gid = 0
            ti.uname = "root"
            ti.gname = "root"

            if entry in ("postinst", "prerm", "postrm", "preinst"):
                ti.mode = 0o755
            else:
                ti.mode = 0o644

            with open(full_path, "rb") as f:
                tar.addfile(ti, f)

    return buf.getvalue()


def write_ar_member(out_f, name: str, data: bytes, mtime: int = 0):
    """Writes a single member entry to an ar archive."""
    header = io.BytesIO()
    # 16 bytes filename padded with spaces
    fn = name.ljust(16)
    header.write(fn.encode("ascii"))
    # 12 bytes mtime
    header.write(str(mtime).ljust(12).encode("ascii"))
    # 6 bytes uid
    header.write("0".ljust(6).encode("ascii"))
    # 6 bytes gid
    header.write("0".ljust(6).encode("ascii"))
    # 8 bytes mode (octal)
    header.write("100644  ".encode("ascii"))
    # 10 bytes size
    header.write(str(len(data)).ljust(10).encode("ascii"))
    # 2 bytes trailer: `\n
    header.write(b"`\n")

    hdr_bytes = header.getvalue()
    if len(hdr_bytes) != 60:
        raise ValueError(f"Header length is {len(hdr_bytes)}, expected 60")

    out_f.write(hdr_bytes)
    out_f.write(data)
    # 2-byte alignment padding
    if len(data) % 2 != 0:
        out_f.write(b"\n")


def build_deb(pkg_dir_path: str, output_deb_path: str):
    pkg_dir = Path(pkg_dir_path).resolve()
    debian_dir = pkg_dir / "DEBIAN"
    if not debian_dir.exists():
        raise FileNotFoundError(f"Missing DEBIAN directory inside {pkg_dir}")

    debian_binary = b"2.0\n"
    control_tar = create_control_tar_gz(debian_dir)
    data_tar = create_tar_gz(pkg_dir, exclude_prefix="DEBIAN")

    now = int(time.time())
    with open(output_deb_path, "wb") as deb_f:
        # Global ar magic: !<arch>\n
        deb_f.write(b"!<arch>\n")
        write_ar_member(deb_f, "debian-binary", debian_binary, mtime=now)
        write_ar_member(deb_f, "control.tar.gz", control_tar, mtime=now)
        write_ar_member(deb_f, "data.tar.gz", data_tar, mtime=now)

    print(f"Successfully generated {output_deb_path} ({os.path.getsize(output_deb_path)} bytes)")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: make_deb.py <pkg_directory> <output_package.deb>")
        sys.exit(1)
    build_deb(sys.argv[1], sys.argv[2])
