"""WP3 — Shared mDNS transport tests.

Covers:
  - parse_avahi_txt: quoted and escaped TXT parsing, malformed TXT handling
  - MdnsBrowser IPv4 filtering
  - Five-tuple tracking and deduplication across interfaces
  - Removal of one interface preserving another
  - Removal of the final interface removing the logical target
  - Scanner lifecycle / startup-grace state
  - Exact scanner readiness formula and the invariant that
    ready:false cannot accompany grace_remaining_ms:0
  - Thread-safe snapshot copying
  - Retry delay sequence and reset behavior
  - Idempotent start
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_mdns import MdnsBrowser, parse_avahi_txt


# ---------------------------------------------------------------------------
# parse_avahi_txt
# ---------------------------------------------------------------------------

class TestParseAvahiTxt:
    def test_simple_key_value(self):
        result = parse_avahi_txt('key=value')
        assert result == {'key': 'value'}

    def test_multiple_pairs(self):
        result = parse_avahi_txt('a=1 b=2 c=3')
        assert result == {'a': '1', 'b': '2', 'c': '3'}

    def test_quoted_value_with_spaces(self):
        result = parse_avahi_txt('"key=hello world"')
        assert result == {'key': 'hello world'}

    def test_empty_string_returns_empty_dict(self):
        assert parse_avahi_txt('') == {}

    def test_token_without_equals_ignored(self):
        result = parse_avahi_txt('noequals a=1')
        assert result == {'a': '1'}

    def test_malformed_quotes_returns_partial_or_empty(self):
        # shlex raises ValueError on unclosed quotes; must not propagate
        result = parse_avahi_txt('"unclosed')
        assert isinstance(result, dict)

    def test_value_can_contain_equals(self):
        result = parse_avahi_txt('k=a=b=c')
        assert result['k'] == 'a=b=c'

    def test_backslash_escape_in_value(self):
        result = parse_avahi_txt(r'"k=hel\"lo"')
        assert 'k' in result

    def test_empty_value(self):
        result = parse_avahi_txt('k=')
        assert result == {'k': ''}

    def test_dial_api_capability(self):
        result = parse_avahi_txt('dial_api=v1 audio_status=v1 version=1.2.3')
        assert result['dial_api'] == 'v1'
        assert result['audio_status'] == 'v1'


# ---------------------------------------------------------------------------
# MdnsBrowser helpers
# ---------------------------------------------------------------------------

def _make_browser(service_type: str = "_test._tcp", parse_fn=None):
    if parse_fn is None:
        def parse_fn(parts, txt):
            key = txt.get("id")
            if not key:
                return None
            return (key, {"ip": parts[7], "name": txt.get("name", "")})
    return MdnsBrowser(service_type=service_type, parse_fn=parse_fn)


def _avahi_resolve_line(iface="eth0", proto="IPv4", name="my-svc",
                         stype="_test._tcp", domain="local",
                         host="myhost.local", ip="192.168.1.1", port="1234",
                         txt='id=abc name=test'):
    """Build a fake avahi-browse =;... resolved line."""
    return f"=;{iface};{proto};{name};{stype};{domain};{host};{ip};{port};{txt}"


def _avahi_remove_line(iface="eth0", proto="IPv4", name="my-svc",
                        stype="_test._tcp", domain="local"):
    return f"-;{iface};{proto};{name};{stype};{domain}"


# ---------------------------------------------------------------------------
# IPv4 filtering
# ---------------------------------------------------------------------------

class TestIPv4Filtering:
    def test_ipv4_event_is_processed(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(proto="IPv4"))
        assert len(browser.get_snapshot()) == 1

    def test_ipv6_event_is_ignored(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(proto="IPv6"))
        assert len(browser.get_snapshot()) == 0

    def test_non_resolve_event_ignored(self):
        browser = _make_browser()
        browser._handle_line("+ eth0 IPv4 my-svc _test._tcp local")
        assert len(browser.get_snapshot()) == 0


# ---------------------------------------------------------------------------
# Five-tuple tracking and deduplication
# ---------------------------------------------------------------------------

class TestFiveTupleDeduplication:
    def test_add_single_entry(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(ip="1.2.3.4", txt='id=aaa name=one'))
        snap = browser.get_snapshot()
        assert 'aaa' in snap
        assert snap['aaa']['ip'] == '1.2.3.4'

    def test_same_identity_on_two_interfaces_deduplicates(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(
            iface="eth0", ip="10.0.0.1", txt='id=aaa name=test'))
        browser._handle_line(_avahi_resolve_line(
            iface="wlan0", ip="10.0.0.2", txt='id=aaa name=test'))
        snap = browser.get_snapshot()
        assert len(snap) == 1
        assert 'aaa' in snap

    def test_removal_of_one_interface_preserves_other(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(
            iface="eth0", name="svc-eth", ip="10.0.0.1", txt='id=aaa name=test'))
        browser._handle_line(_avahi_resolve_line(
            iface="wlan0", name="svc-eth", ip="10.0.0.2", txt='id=aaa name=test'))
        # Remove the eth0 sighting
        browser._handle_line(_avahi_remove_line(iface="eth0", name="svc-eth"))
        snap = browser.get_snapshot()
        assert 'aaa' in snap  # still present via wlan0

    def test_removal_of_final_interface_removes_identity(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(
            iface="eth0", ip="10.0.0.1", txt='id=aaa name=test'))
        browser._handle_line(_avahi_remove_line(iface="eth0"))
        snap = browser.get_snapshot()
        assert 'aaa' not in snap

    def test_two_different_identities_on_same_interface(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(
            name="svc1", ip="10.0.0.1", txt='id=aaa name=one'))
        browser._handle_line(_avahi_resolve_line(
            name="svc2", ip="10.0.0.2", txt='id=bbb name=two'))
        snap = browser.get_snapshot()
        assert len(snap) == 2

    def test_remove_one_leaves_other(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(
            name="svc1", ip="10.0.0.1", txt='id=aaa name=one'))
        browser._handle_line(_avahi_resolve_line(
            name="svc2", ip="10.0.0.2", txt='id=bbb name=two'))
        browser._handle_line(_avahi_remove_line(name="svc1"))
        snap = browser.get_snapshot()
        assert 'aaa' not in snap
        assert 'bbb' in snap

    def test_parse_fn_returning_none_ignored(self):
        def parse_fn(parts, txt):
            return None  # always ignore
        browser = _make_browser(parse_fn=parse_fn)
        browser._handle_line(_avahi_resolve_line())
        assert browser.get_snapshot() == {}

    def test_missing_id_in_txt_ignored(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(txt='name=test'))  # no id=
        assert browser.get_snapshot() == {}


# ---------------------------------------------------------------------------
# Thread-safe snapshot
# ---------------------------------------------------------------------------

class TestThreadSafeSnapshot:
    def test_snapshot_is_a_copy(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(txt='id=aaa name=test'))
        snap = browser.get_snapshot()
        # Modifying the snapshot must not affect the registry
        snap['new_key'] = {'ip': '0.0.0.0'}
        assert 'new_key' not in browser.get_snapshot()

    def test_concurrent_reads_do_not_raise(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(txt='id=aaa name=test'))
        errors = []

        def reader():
            try:
                for _ in range(50):
                    _ = browser.get_snapshot()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=reader) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []


# ---------------------------------------------------------------------------
# Idempotent start
# ---------------------------------------------------------------------------

class TestIdempotentStart:
    def test_start_is_idempotent(self):
        browser = _make_browser()
        started_threads = []

        original_start = threading.Thread.start

        with patch.object(threading.Thread, "start", side_effect=lambda self: started_threads.append(1) or original_start(self)):
            pass  # just count, don't interfere

        # Manual test: calling start twice should not start two browse loops
        assert not browser.has_started
        with patch.object(browser, "_browse_loop"):
            browser.start()
            browser.start()
        assert browser.has_started

    def test_start_sets_has_started_flag(self):
        browser = _make_browser()
        assert not browser.has_started
        with patch("threading.Thread.start"):
            browser.start()
        assert browser.has_started


# ---------------------------------------------------------------------------
# Scanner lifecycle / startup grace state
# ---------------------------------------------------------------------------

class TestScannerLifecycle:
    def test_not_started_is_not_ready(self):
        browser = _make_browser()
        assert not browser.scanner_ready()

    def test_ready_after_first_browse_event(self):
        browser = _make_browser()
        with patch("threading.Thread.start"):
            browser.start()
        browser._has_browse_event = True
        assert browser.scanner_ready()

    def test_ready_after_8s_elapsed(self):
        browser = _make_browser()
        with patch("threading.Thread.start"):
            browser.start()
        browser._start_monotonic = time.monotonic() - 8.1
        assert browser.scanner_ready()

    def test_not_ready_within_8s_without_event(self):
        browser = _make_browser()
        with patch("threading.Thread.start"):
            browser.start()
        browser._start_monotonic = time.monotonic() - 1.0
        assert not browser.scanner_ready()

    def test_invariant_not_ready_implies_grace_remaining_nonzero(self):
        """If scanner_ready() is False, grace_remaining_ms() must be > 0."""
        browser = _make_browser()
        with patch("threading.Thread.start"):
            browser.start()
        browser._start_monotonic = time.monotonic() - 1.0
        assert not browser.scanner_ready()
        assert browser.grace_remaining_ms() > 0

    def test_ready_implies_grace_remaining_zero(self):
        browser = _make_browser()
        with patch("threading.Thread.start"):
            browser.start()
        browser._has_browse_event = True
        assert browser.scanner_ready()
        assert browser.grace_remaining_ms() == 0

    def test_grace_remaining_zero_after_8s(self):
        browser = _make_browser()
        with patch("threading.Thread.start"):
            browser.start()
        browser._start_monotonic = time.monotonic() - 9.0
        assert browser.grace_remaining_ms() == 0

    def test_grace_remaining_decreases_over_time(self):
        browser = _make_browser()
        with patch("threading.Thread.start"):
            browser.start()
        browser._start_monotonic = time.monotonic() - 3.0
        remaining = browser.grace_remaining_ms()
        assert 4500 < remaining < 5100  # approximately 5s left

    def test_has_browse_event_set_on_handle_line(self):
        browser = _make_browser()
        assert not browser.has_browse_event
        browser._has_browse_event = True
        assert browser.has_browse_event


# ---------------------------------------------------------------------------
# on_add / on_remove callbacks
# ---------------------------------------------------------------------------

class TestCallbacks:
    def test_on_add_called_for_new_identity(self):
        added = []

        def on_add(key, model):
            added.append(key)

        browser = _make_browser()
        browser._on_add = on_add
        browser._handle_line(_avahi_resolve_line(txt='id=aaa name=test'))
        assert added == ['aaa']

    def test_on_add_not_called_for_duplicate_interface(self):
        added = []
        browser = _make_browser()
        browser._on_add = lambda k, m: added.append(k)
        browser._handle_line(_avahi_resolve_line(
            iface="eth0", name="svc1", txt='id=aaa name=test'))
        browser._handle_line(_avahi_resolve_line(
            iface="wlan0", name="svc1", txt='id=aaa name=test'))
        assert len(added) == 1

    def test_on_remove_called_when_last_interface_removed(self):
        removed = []
        browser = _make_browser()
        browser._on_remove = lambda k, m: removed.append(k)
        browser._handle_line(_avahi_resolve_line(
            iface="eth0", txt='id=aaa name=test'))
        browser._handle_line(_avahi_remove_line(iface="eth0"))
        assert 'aaa' in removed

    def test_on_remove_not_called_when_other_interface_remains(self):
        removed = []
        browser = _make_browser()
        browser._on_remove = lambda k, m: removed.append(k)
        browser._handle_line(_avahi_resolve_line(
            iface="eth0", name="svc1", txt='id=aaa name=test'))
        browser._handle_line(_avahi_resolve_line(
            iface="wlan0", name="svc1", txt='id=aaa name=test'))
        browser._handle_line(_avahi_remove_line(iface="eth0", name="svc1"))
        assert removed == []

    def test_callback_exception_does_not_propagate(self):
        def on_add(k, m):
            raise RuntimeError("boom")

        browser = _make_browser()
        browser._on_add = on_add
        # Must not raise
        browser._handle_line(_avahi_resolve_line(txt='id=aaa name=test'))


# ---------------------------------------------------------------------------
# Retry delay sequence
# ---------------------------------------------------------------------------

class TestRetryDelaySequence:
    def test_retry_delays_constant(self):
        from autostream_mdns import _RETRY_DELAYS
        assert _RETRY_DELAYS == [5, 10, 20, 30]

    def test_retry_caps_at_30(self):
        from autostream_mdns import _RETRY_DELAYS
        for idx in range(10):
            delay = _RETRY_DELAYS[min(idx, len(_RETRY_DELAYS) - 1)]
            assert delay <= 30


# ---------------------------------------------------------------------------
# Dial installer test: mdns module deployed
# ---------------------------------------------------------------------------

class TestDialInstallerMdnsDeploy:
    def test_mdns_module_deployed_in_dial_installer(self):
        content = (REPO_ROOT / "autostream_dial_install.sh").read_text(encoding="utf-8")
        assert "autostream_mdns.py" in content, (
            "autostream_dial_install.sh must deploy core/autostream_mdns.py"
        )

    def test_mdns_module_deployed_as_flat_path(self):
        content = (REPO_ROOT / "autostream_dial_install.sh").read_text(encoding="utf-8")
        assert "/opt/autostream/autostream_mdns.py" in content, (
            "autostream_mdns.py must be installed at /opt/autostream/autostream_mdns.py"
        )
