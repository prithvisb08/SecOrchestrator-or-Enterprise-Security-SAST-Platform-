import io
import tarfile
import tempfile
import zipfile

import pytest

from security_platform.core.errors import ArchiveSecurityError
from security_platform.ingestion.loaders import ArchiveLoader


def test_zip_slip_rejected():
    """True-Positive: Zip-slip archive containing relative path traversal is rejected."""
    with tempfile.NamedTemporaryFile(suffix=".zip") as tmp:
        with zipfile.ZipFile(tmp, "w") as zf:
            zf.writestr("../../etc/shadow", "root:*:0:0:root:/root:/bin/bash")
        with pytest.raises(ArchiveSecurityError, match="[Pp]ath traversal|[Zz]ip slip"):
            ArchiveLoader(tmp.name)


def test_zip_slip_windows_backslash_rejected():
    """True-Positive: Zip-slip archive containing backslash traversal is rejected."""
    with tempfile.NamedTemporaryFile(suffix=".zip") as tmp:
        with zipfile.ZipFile(tmp, "w") as zf:
            zf.writestr("..\\..\\windows\\system32\\calc.exe", "fake-exe")
        with pytest.raises(ArchiveSecurityError, match="[Pp]ath traversal|[Zz]ip slip"):
            ArchiveLoader(tmp.name)


def test_zip_bomb_decompression_size_limit():
    """True-Positive: Archive expanding beyond MAX_EXTRACT_SIZE is aborted."""
    with tempfile.NamedTemporaryFile(suffix=".zip") as tmp:
        with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # 1MB of null bytes compresses to ~1KB
            zf.writestr("huge_file.txt", b"\0" * (1024 * 1024))
        # Set artificially small limit for test
        loader = ArchiveLoader.__new__(ArchiveLoader)
        loader.archive_path = tmp.name
        loader.MAX_EXTRACT_SIZE = 512 * 1024  # 512 KB
        loader._temp_dir = tempfile.TemporaryDirectory()
        with pytest.raises(ArchiveSecurityError, match="[Ee]xceeded maximum extraction size"):
            loader._extract_securely()
        loader.cleanup()


def test_zip_max_file_count_limit():
    """True-Positive: Archive containing too many files is aborted."""
    with tempfile.NamedTemporaryFile(suffix=".zip") as tmp:
        with zipfile.ZipFile(tmp, "w") as zf:
            for i in range(15):
                zf.writestr(f"file_{i}.txt", "test")
        loader = ArchiveLoader.__new__(ArchiveLoader)
        loader.archive_path = tmp.name
        loader.MAX_FILE_COUNT = 10  # 10 files max
        loader._temp_dir = tempfile.TemporaryDirectory()
        with pytest.raises(ArchiveSecurityError, match="[Ee]xceeded maximum file count"):
            loader._extract_securely()
        loader.cleanup()


def test_zip_symlink_member_rejected():
    """True-Positive: Symlink archive members are rejected."""
    with tempfile.NamedTemporaryFile(suffix=".zip") as tmp:
        with zipfile.ZipFile(tmp, "w") as zf:
            zinfo = zipfile.ZipInfo("symlink_to_etc")
            # Set UNIX symlink mode (0o120000)
            zinfo.external_attr = (0o120777) << 16
            zf.writestr(zinfo, "/etc/passwd")
        with pytest.raises(ArchiveSecurityError, match="[Ss]ymlink"):
            ArchiveLoader(tmp.name)


def test_safe_zip_extraction():
    """True-Negative: Normal valid zip extracts cleanly."""
    with tempfile.NamedTemporaryFile(suffix=".zip") as tmp:
        with zipfile.ZipFile(tmp, "w") as zf:
            zf.writestr("src/main.py", "print('hello world')")
            zf.writestr("README.md", "# Sample Project")
        loader = ArchiveLoader(tmp.name)
        workspace = loader.get_workspace()
        assert (workspace / "src/main.py").exists()
        assert (workspace / "src/main.py").read_text() == "print('hello world')"
        loader.cleanup()


def test_safe_tar_gz_extraction():
    """True-Negative: Normal valid tar.gz extracts cleanly."""
    with tempfile.NamedTemporaryFile(suffix=".tar.gz") as tmp:
        with tarfile.open(tmp.name, "w:gz") as tar:
            data = b"print('tar hello')"
            ti = tarfile.TarInfo(name="main.py")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
        loader = ArchiveLoader(tmp.name)
        workspace = loader.get_workspace()
        assert (workspace / "main.py").exists()
        assert (workspace / "main.py").read_bytes() == data
        loader.cleanup()
