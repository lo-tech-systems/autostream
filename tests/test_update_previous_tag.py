"""The release a dial update replaces is for display; it never decides whether
the update is applied.

An install can record a release tag that is not a version (a branch name on a
development install, "unknown"), and the service account can write anything
into the files that record it. That value is carried into the hand-off the
boot step reads. The boot step used to refuse the whole hand-off over it, so
the update was never applied. The new tag is still checked strictly; a
previous tag that is not a plain version is blanked, by the installer that
writes it and by the boot step that reads it, and the shell and Python
definitions of "plain version" are tested against the same cases.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_dial_staged_install import (  # noqa: E402
    Env, REPO_ROOT, VARS, _kv, bash_capable, posix_only,
)
from test_dial_update_boot import (  # noqa: E402,F401  (fixtures are used by name)
    PREV, TAG, clock, mod, swapped_tree, system, world,
)
import autostream_update_support as _asu  # noqa: E402

# (tag, is a plain version)
TAG_CASES = [
    ("1.2.0", True), ("v1.2.0", True), ("1", True), ("1.2", True),
    ("0.7.0-beta.1", True), ("1.2.3-rc.2", True), ("1.2.3-rc", True),
    ("1.2.3+build.5", True), ("a" * 5, False),
    ("unknown", False), ("", False), ("mybranch", False), ("main", False),
    ("feature-x", False), ("abc123", False),     ("1.2.0; reboot", False), ("$(id)", False), ("`id`", False), ("../x", False),
    ("..", False), (".hidden", False), ("-1.2.0", False), ("1.2.0\\n", False),
    ("v", False), ("1.2.x", False), ("1..2", False), ("1.2.3-", False),
    ("1" * 64, True), ("1" * 65, False), ("refs/tags/v1.2.0", False),
]

HOSTILE_OR_ODD = ["mybranch", "unknown", "", "main", "1.2.0; touch /tmp/x", "$(id)", "..", ".hidden"]


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


@bash_capable
class TestOneDefinitionOfAPlainVersion:
    @pytest.mark.parametrize("tag, plain", TAG_CASES)
    def test_the_shell_and_python_sides_agree(self, env, tag, plain):
        env.put("tag", tag)
        r = env.run('_tag_or_empty "$(cat "$TAG_FILE")"',
                    TAG_FILE=(env.root / "tag").as_posix())
        assert r.returncode == 0, r.stderr
        assert (r.stdout.strip() != "") is plain
        assert not plain or r.stdout.strip() == tag
        assert _asu.valid_release_tag(tag) is plain


@bash_capable
@posix_only
class TestTheInstallerBlanksAPreviousTagThatIsNotAVersion:
    @pytest.mark.parametrize("recorded", HOSTILE_OR_ODD)
    def test_the_hand_off_carries_no_such_previous_tag(self, env, mod, recorded):
        env.install_state.write_text(
            f"AUTOSTREAM_PRODUCT=autostream-dial\nAUTOSTREAM_RELEASE_TAG={recorded}\n",
            encoding="utf-8")
        r = env.run(
            'PREVIOUS_RELEASE_TAG="$(_installed_release_tag)"\n'
            'phase prepare 5 "Preparing"\n'
            'NEW_VENV=venv.1.3.0; PREVIOUS_VENV=venv.1.2.0\nwrite_update_swap')
        assert r.returncode == 0, r.stderr
        swap_text = env.swap.read_text(encoding="utf-8")
        assert _kv(swap_text)["PREVIOUS_TAG"] == ""
        assert _kv(swap_text)["TAG"] == "1.3.0"
        assert _kv(env.result.read_text(encoding="utf-8")).get("PREVIOUS_TAG", "") == ""
        assert mod._swap_problem(mod._parse_env_text(swap_text)) == ""

    def test_a_version_is_carried_as_it_is(self, env):
        env.install_state.write_text("AUTOSTREAM_RELEASE_TAG=1.2.0\n", encoding="utf-8")
        r = env.run(
            'PREVIOUS_RELEASE_TAG="$(_installed_release_tag)"\n'
            'phase prepare 5 "Preparing"\nNEW_VENV=venv.1.3.0; PREVIOUS_VENV=venv.1.2.0\nwrite_update_swap')
        assert r.returncode == 0, r.stderr
        assert _kv(env.swap.read_text(encoding="utf-8"))["PREVIOUS_TAG"] == "1.2.0"

    @pytest.mark.parametrize("recorded", ["..", ".hidden", "mybranch", "$(id)"])
    def test_the_old_virtualenv_is_not_named_after_it(self, env, recorded):
        env.venv("venv")
        env.install_state.write_text(f"AUTOSTREAM_RELEASE_TAG={recorded}\n", encoding="utf-8")
        r = env.run(f"prepare_update_venv\n{VARS}", PREVIOUS_RELEASE_TAG=recorded)
        assert r.returncode == 0, r.stderr
        assert _kv(r.stdout)["PREVIOUS_VENV"] == "venv.previous"

    def test_the_failure_message_does_not_repeat_it(self, env):
        env.install_state.write_text("AUTOSTREAM_RELEASE_TAG=$(id)\n", encoding="utf-8")
        r = env.run('CURRENT_PHASE=files\nupdate_failure_message')
        assert r.returncode == 0, r.stderr
        assert "$(id)" not in r.stdout
        assert "previous version kept" in r.stdout


@posix_only
class TestTheBootStepAppliesTheUpdateAnyway:
    @pytest.mark.parametrize("previous", HOSTILE_OR_ODD)
    def test_a_previous_tag_that_is_not_a_version_does_not_block_the_swap(
            self, world, mod, system, previous):
        world.build_staged(first_update=False, migrate=False)
        lines = [ln for ln in world.swap_file.read_text(encoding="utf-8").splitlines()
                 if not ln.startswith("PREVIOUS_TAG=")]
        world.swap_file.write_text("\n".join(lines + [f"PREVIOUS_TAG={previous}"]) + "\n",
                                   encoding="utf-8")
        result = mod.cmd_boot()
        assert result["ok"] is True
        assert world.live_files() == swapped_tree(first_update=False)
        assert system.verify_scheduled()
        env = world.result()
        assert env["STATUS"] == "in_progress" and env["TAG"] == TAG
        assert env.get("PREVIOUS_TAG", "") == ""

    def test_the_real_previous_tag_still_reaches_the_result(self, world, mod):
        world.build_staged(first_update=False, migrate=False)
        mod.cmd_boot()
        assert world.result()["PREVIOUS_TAG"] == PREV

    @pytest.mark.parametrize("new", ["mybranch", "1.3.0; touch /tmp/x", "$(id)", ".."])
    def test_a_new_tag_that_is_not_a_version_is_still_refused(
            self, world, mod, system, new):
        world.build_staged(first_update=False, migrate=False)
        lines = [ln for ln in world.swap_file.read_text(encoding="utf-8").splitlines()
                 if not ln.startswith("TAG=")]
        world.swap_file.write_text("\n".join(lines + [f"TAG={new}"]) + "\n", encoding="utf-8")
        before = world.live_files()
        mod.cmd_boot()
        assert world.live_files() == before
        assert not system.verify_scheduled()
        assert system.reboots == 0
        assert world.result()["STATUS"] == "failure"

    def test_a_result_file_with_an_odd_previous_tag_does_not_reach_the_messages(
            self, world, mod):
        world.build_staged(first_update=False, migrate=False)
        text = world.result_file.read_text(encoding="utf-8")
        world.result_file.write_text(
            "\n".join(ln for ln in text.splitlines() if not ln.startswith("PREVIOUS_TAG="))
            + "\nPREVIOUS_TAG=<b>x</b>\n", encoding="utf-8")
        assert mod._previous_tag("<b>x</b>") == ""
        assert mod._previous_tag("v1.2.0") == "1.2.0"
        assert mod._previous_tag(None) == ""
