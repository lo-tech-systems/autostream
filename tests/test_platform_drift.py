"""Regression test: platform/ module copies must stay in sync with core/.

The platform/ directory contains files that are also present in core/.
If they diverge, the deployed system runs different code from what is
developed and tested locally.

When updating either copy, update both at the same time.
"""
import hashlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent

MIRRORED_PAIRS = [
    ("platform/autostream_sysutils.py", "core/autostream_sysutils.py"),
    ("platform/autostream_rpi.py",      "core/autostream_rpi.py"),
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("src, dst", MIRRORED_PAIRS, ids=[p[0].split("/")[-1] for p in MIRRORED_PAIRS])
def test_platform_and_core_copies_are_identical(src: str, dst: str) -> None:
    """platform/ and core/ copies of shared modules must be byte-for-byte identical.

    If this test fails, update both files together and commit them in the same
    change so the divergence window is zero.
    """
    src_path = REPO_ROOT / src
    dst_path = REPO_ROOT / dst

    assert src_path.exists(), f"Source file missing: {src}"
    assert dst_path.exists(), f"Destination file missing: {dst}"

    src_hash = _sha256(src_path)
    dst_hash = _sha256(dst_path)

    assert src_hash == dst_hash, (
        f"{src} and {dst} have diverged.\n"
        f"  {src}: {src_hash}\n"
        f"  {dst}: {dst_hash}\n"
        "Update both files together."
    )
