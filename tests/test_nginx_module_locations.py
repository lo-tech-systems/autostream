"""tests/test_nginx_module_locations.py

The shipped site serves the ES module directories with a revalidating
Cache-Control, because the modules an entry module imports are reached by
relative URLs that carry no ?v=. Read from the config text, so it runs where
nginx is not installed.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

CONF = (Path(__file__).resolve().parent.parent / "system" / "nginx" / "autostream-nginx.conf").read_text(
    encoding="utf-8")


def _block(prefix: str) -> str:
    m = re.search(r"location\s+" + re.escape(prefix) + r"\s*\{([^}]*)\}", CONF)
    assert m, f"no location {prefix}"
    return m.group(1)


@pytest.mark.parametrize("prefix", ["/static/shared/", "/static/page/home/"])
def test_a_module_directory_is_aliased_and_revalidated(prefix):
    body = _block(prefix)
    assert re.search(r"alias\s+/opt/autostream/nginx" + re.escape(prefix) + r"\s*;", body)
    assert re.search(r'add_header\s+Cache-Control\s+"no-cache"\s*;', body)
    assert "max-age" not in body


def test_the_general_static_location_keeps_its_one_hour_cache():
    body = _block("/static/")
    assert 'add_header Cache-Control "public, max-age=3600";' in body
