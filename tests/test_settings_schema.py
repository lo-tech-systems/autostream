"""Unit tests for the declarative settings schema table.

Covers:

1. FieldSpec/register_field mechanics in isolation (no dependency on which
   of the four migrated call sites has run yet).
2. Once autostream_webui_api is imported (which registers _SETTINGS_FIELDS'
   ~24 rows into SETTINGS_SCHEMA at import time), every one of those rows
   is present with the expected section/key/validate/live wiring.
3. An unknown path is a documented, non-raising ``None`` lookup miss (see
   the schema module's own docstring for why that is the chosen behaviour
   ahead of a first-class enforcement layer, which is out of scope here).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)


# ---------------------------------------------------------------------------
# 1. FieldSpec / register_field mechanics
# ---------------------------------------------------------------------------

class TestFieldSpecAndRegister:
    def test_register_field_roundtrip(self):
        from autostream_settings_schema import SETTINGS_SCHEMA, register_field

        def _v(value):
            return value

        spec = register_field("test.roundtrip_field", "test_section", "roundtrip_field", _v)
        try:
            assert spec.path == "test.roundtrip_field"
            assert spec.section == "test_section"
            assert spec.key == "roundtrip_field"
            assert spec.validate is _v
            assert SETTINGS_SCHEMA["test.roundtrip_field"] is spec
        finally:
            del SETTINGS_SCHEMA["test.roundtrip_field"]

    def test_register_field_with_live_and_form_coerce(self):
        from autostream_settings_schema import SETTINGS_SCHEMA, register_field

        def _v(value):
            return value

        def _live(state, value):
            return True

        def _fc(raw):
            return raw

        spec = register_field(
            "test.full_field", "test_section", "full_field", _v,
            live=_live, form_coerce=_fc,
        )
        try:
            assert spec.live_fn is _live
            assert spec.form_coerce is _fc
        finally:
            del SETTINGS_SCHEMA["test.full_field"]

    def test_unknown_path_lookup_is_none_not_raise(self):
        from autostream_settings_schema import SETTINGS_SCHEMA, get_field_spec

        assert "this.path.was.never.registered" not in SETTINGS_SCHEMA
        assert get_field_spec("this.path.was.never.registered") is None

    def test_registering_same_path_twice_replaces_not_duplicates(self):
        from autostream_settings_schema import SETTINGS_SCHEMA, register_field

        def _v1(value):
            return value

        def _v2(value):
            return value

        register_field("test.replace_field", "s", "k", _v1)
        try:
            spec2 = register_field("test.replace_field", "s", "k", _v2)
            assert SETTINGS_SCHEMA["test.replace_field"] is spec2
            assert SETTINGS_SCHEMA["test.replace_field"].validate is _v2
        finally:
            del SETTINGS_SCHEMA["test.replace_field"]


# ---------------------------------------------------------------------------
# 2. _SETTINGS_FIELDS migration (autostream_webui_api.py, POST /api/settings)
# ---------------------------------------------------------------------------

# The exact ~24 dotted paths _SETTINGS_FIELDS declares, per
# autostream_webui_api.py. Any path present in _SETTINGS_FIELDS but absent
# here (or vice versa) is exactly the kind of drift this table exists to
# prevent -- see test_settings_fields_rows_all_present_in_schema below.
_EXPECTED_SETTINGS_FIELD_PATHS = frozenset({
    "webui.dark_mode",
    "webui.show_master_volume",
    "webui.show_input_detail",
    "webui.show_hostname_on_home",
    "webui.control_other_appliances",
    "webui.output_usage_poll_interval_seconds",
    "updates.update_channel",
    "audio1.gain_db",
    "audio2.gain_db",
    "audio1.eq_40hz_db",
    "audio1.eq_100hz_db",
    "audio1.eq_8khz_db",
    "audio2.eq_40hz_db",
    "audio2.eq_100hz_db",
    "audio2.eq_8khz_db",
    "owntone.output_name",
    "owntone.volume_percent",
    "general.silence_seconds",
    "general.audio_path",
    "audio1.capture_device",
    "audio2.capture_device",
    "audio1.enabled",
    "audio2.enabled",
    "audio1.turntable",
    "audio2.turntable",
    "track_identification.enabled",
    "track_identification.analysis_lead_in_seconds",
    "track_identification.refresh_seconds",
    "track_identification.track_change_silence_seconds",
    "repeat.enabled",
    "repeat.codec",
    "repeat.target_minutes",
})


class TestSettingsFieldsMigration:
    def test_settings_fields_rows_all_present_in_schema(self):
        import autostream_webui_api as api
        from autostream_settings_schema import SETTINGS_SCHEMA

        assert set(api._SETTINGS_FIELDS.keys()) == _EXPECTED_SETTINGS_FIELD_PATHS
        for path in _EXPECTED_SETTINGS_FIELD_PATHS:
            assert path in SETTINGS_SCHEMA, f"{path} missing from SETTINGS_SCHEMA"

    def test_schema_row_matches_settings_fields_tuple(self):
        import autostream_webui_api as api
        from autostream_settings_schema import SETTINGS_SCHEMA

        for path, (section, key, validate, live) in api._SETTINGS_FIELDS.items():
            spec = SETTINGS_SCHEMA[path]
            assert spec.section == section
            assert spec.key == key
            assert spec.validate is validate
            assert spec.live_fn is live

    def test_gain_db_bounds_enforced_via_schema_validate(self):
        import autostream_webui_api as api  # noqa: F401
        from autostream_settings_schema import SETTINGS_SCHEMA

        spec = SETTINGS_SCHEMA["audio1.gain_db"]
        assert spec.validate(5.0) == pytest.approx(5.0)
        with pytest.raises(ValueError, match="Value must be between -10 and 10"):
            spec.validate(11.0)

    def test_bool_field_error_message_unchanged(self):
        import autostream_webui_api as api  # noqa: F401
        from autostream_settings_schema import SETTINGS_SCHEMA

        spec = SETTINGS_SCHEMA["webui.dark_mode"]
        with pytest.raises(ValueError, match="Value must be true or false"):
            spec.validate("not-a-bool")

    def test_track_id_fields_carry_form_coerce_for_setup_form(self):
        import autostream_webui_api as api  # noqa: F401
        from autostream_settings_schema import SETTINGS_SCHEMA

        for path in (
            "track_identification.analysis_lead_in_seconds",
            "track_identification.refresh_seconds",
            "track_identification.track_change_silence_seconds",
            "webui.output_usage_poll_interval_seconds",
        ):
            spec = SETTINGS_SCHEMA[path]
            assert spec.form_coerce is not None, f"{path} missing form_coerce"
            # form_coerce must accept a raw form string, matching what
            # handle_setup_post has always passed it (never a typed value).
            assert spec.form_coerce("3") is not None


# ---------------------------------------------------------------------------
# 3. _SERVICE_FIELD_MAP migration (autostream_webui_api.py, POST /api/service/config)
# ---------------------------------------------------------------------------

class TestServiceFieldMapMigration:
    def test_service_field_map_rows_all_present_in_schema(self):
        import autostream_webui_api as api
        from autostream_settings_schema import SETTINGS_SCHEMA

        assert len(api._SERVICE_FIELD_MAP) == 10  # stylus x2 + (belt + bearing) x2 x2
        for path in api._SERVICE_FIELD_MAP:
            assert path in SETTINGS_SCHEMA, f"{path} missing from SETTINGS_SCHEMA"

    def test_schema_row_matches_service_field_map_tuple(self):
        import autostream_webui_api as api
        from autostream_settings_schema import SETTINGS_SCHEMA

        for path, (section, key, normaliser) in api._SERVICE_FIELD_MAP.items():
            spec = SETTINGS_SCHEMA[path]
            assert spec.section == section
            assert spec.key == key
            assert spec.normalise is normaliser

    def test_stylus_hours_normaliser_reachable_via_schema(self):
        import autostream_webui_api as api  # noqa: F401
        from autostream_settings_schema import SETTINGS_SCHEMA

        spec = SETTINGS_SCHEMA["service_stylus_life_hours_input1"]
        assert spec.section == "audio1"
        assert spec.key == "stylus_life_hours"
        assert spec.normalise is not None


# ---------------------------------------------------------------------------
# 4. output_eq migration (autostream_appliance_models.py, apply_eq_field/reset)
# ---------------------------------------------------------------------------

class TestOutputEqMigration:
    def test_all_seven_output_eq_fields_registered(self):
        import autostream_appliance_models as am
        from autostream_settings_schema import SETTINGS_SCHEMA

        for field in am._OUTPUT_EQ_ALL_FIELDS:
            path = f"output_eq.{field}"
            assert path in SETTINGS_SCHEMA, f"{path} missing from SETTINGS_SCHEMA"
            spec = SETTINGS_SCHEMA[path]
            assert spec.section == "output_eq"
            assert spec.key == field
            assert spec.validate is not None

    def test_db_field_clamps_same_as_before_migration(self):
        import autostream_appliance_models as am  # noqa: F401
        from autostream_settings_schema import SETTINGS_SCHEMA

        spec = SETTINGS_SCHEMA["output_eq.gain_db"]
        assert spec.validate("5.0") == pytest.approx(5.0)
        # Out-of-range values are clamped, not rejected -- same as the
        # inline `max(_OUTPUT_EQ_DB_MIN, min(_OUTPUT_EQ_DB_MAX, value))`
        # apply_eq_field() used before this migration.
        assert spec.validate("999") == pytest.approx(am._OUTPUT_EQ_DB_MAX)
        assert spec.validate("-999") == pytest.approx(am._OUTPUT_EQ_DB_MIN)

    def test_db_field_non_numeric_error_message_unchanged(self):
        import autostream_appliance_models as am  # noqa: F401
        from autostream_settings_schema import SETTINGS_SCHEMA

        spec = SETTINGS_SCHEMA["output_eq.peq1_db"]
        with pytest.raises(ValueError, match="Value must be numeric"):
            spec.validate("not-a-number")

    def test_bool_field_normalises_same_truthy_strings_as_before_migration(self):
        import autostream_appliance_models as am  # noqa: F401
        from autostream_settings_schema import SETTINGS_SCHEMA

        spec = SETTINGS_SCHEMA["output_eq.auto_trim_enabled"]
        for truthy in ("true", "1", "yes", "TRUE", "Yes"):
            assert spec.validate(truthy) is True
        for falsy in ("false", "0", "no", ""):
            assert spec.validate(falsy) is False


# ---------------------------------------------------------------------------
# 5. handle_setup_post migration (autostream_webui_post_handlers.py, POST /setup)
#
# Only the fields whose form-path normalisation was already identical to the
# JSON API's schema-declared normaliser are migrated here -- see the scope
# comment above handle_setup_post() in autostream_webui_post_handlers.py for
# why the rest (gain_db, EQ bands, silence_seconds, ...) are deliberately
# left untouched by this item.
# ---------------------------------------------------------------------------

class TestSetupPostMigration:
    def test_setup_post_module_reaches_form_coerce_rows_via_schema(self):
        import autostream_webui_post_handlers as post_handlers  # noqa: F401
        from autostream_settings_schema import SETTINGS_SCHEMA

        for path in (
            "webui.output_usage_poll_interval_seconds",
            "track_identification.analysis_lead_in_seconds",
            "track_identification.refresh_seconds",
            "track_identification.track_change_silence_seconds",
        ):
            assert SETTINGS_SCHEMA[path].form_coerce is not None

    def test_poll_interval_form_coerce_out_of_range_falls_back_to_default(self):
        # Matches normalize_output_usage_poll_interval()'s own documented
        # "out-of-range -> normalized to default (3)" contract, now reached
        # via the schema row instead of a direct import.
        import autostream_webui_post_handlers as post_handlers  # noqa: F401
        from autostream_settings_schema import SETTINGS_SCHEMA

        spec = SETTINGS_SCHEMA["webui.output_usage_poll_interval_seconds"]
        assert spec.form_coerce("999999") == 3


# ---------------------------------------------------------------------------
# 6. Wildcard/template schema rows for per-output settings
#    (autostream_webui_api.py, "owntone.offsets.*" / "owntone.airplay_modes.*")
# ---------------------------------------------------------------------------

class TestWildcardTemplateRows:
    def test_template_row_registered_with_literal_star(self):
        import autostream_webui_api as api  # noqa: F401
        from autostream_settings_schema import SETTINGS_SCHEMA

        assert "owntone.offsets.*" in SETTINGS_SCHEMA
        assert "owntone.airplay_modes.*" in SETTINGS_SCHEMA

    def test_get_field_spec_matches_concrete_output_id(self):
        import autostream_webui_api as api  # noqa: F401
        from autostream_settings_schema import SETTINGS_SCHEMA, get_field_spec

        spec = get_field_spec("owntone.offsets.abc123")
        assert spec is SETTINGS_SCHEMA["owntone.offsets.*"]

    def test_get_field_spec_exact_match_takes_priority_over_template(self):
        import autostream_webui_api as api  # noqa: F401 -- ensure the real row exists first
        from autostream_settings_schema import register_field, get_field_spec, SETTINGS_SCHEMA

        original = SETTINGS_SCHEMA.get("owntone.offsets.*")
        register_field("owntone.offsets.*", "owntone", "offsets", lambda v: v)
        register_field("owntone.offsets.exact", "owntone", "offsets", lambda v: "exact-row")
        try:
            spec = get_field_spec("owntone.offsets.exact")
            assert spec.validate(1) == "exact-row"
        finally:
            del SETTINGS_SCHEMA["owntone.offsets.exact"]
            if original is not None:
                SETTINGS_SCHEMA["owntone.offsets.*"] = original
            else:
                del SETTINGS_SCHEMA["owntone.offsets.*"]

    def test_template_leaf_extracts_wildcard_segment(self):
        from autostream_settings_schema import template_leaf

        assert template_leaf("owntone.offsets.*", "owntone.offsets.abc123") == "abc123"
        assert template_leaf("owntone.offsets.*", "owntone.offsets.") is None
        assert template_leaf("owntone.offsets.*", "audio1.gain_db") is None
        assert template_leaf("audio1.gain_db", "audio1.gain_db") is None  # no "*" -> not a template

    def test_offset_clamp_matches_pre_migration_bounds(self):
        import autostream_webui_api as api  # noqa: F401
        from autostream_settings_schema import get_field_spec

        spec = get_field_spec("owntone.offsets.abc123")
        assert spec.validate(999999) == 2000
        assert spec.validate(-999999) == -2000
        assert spec.validate(0) == 0
        with pytest.raises(ValueError, match="offset_ms must be a number"):
            spec.validate("not-a-number")

    def test_airplay_mode_enum_matches_valid_airplay_modes(self):
        import autostream_webui_api as api  # noqa: F401
        from autostream_config import VALID_AIRPLAY_MODES
        from autostream_settings_schema import get_field_spec

        spec = get_field_spec("owntone.airplay_modes.abc123")
        assert spec.enum == frozenset(VALID_AIRPLAY_MODES)

    def test_settings_store_set_writes_into_nested_output_dict(self, tmp_path):
        import json
        import autostream_webui_api as api  # noqa: F401
        from autostream_settings import SettingsStore

        p = tmp_path / "cfg.json"
        p.write_text(json.dumps({}))
        store = SettingsStore(str(p), _save_interval_seconds=60.0, _writer=lambda path, data: None)
        try:
            store.set("owntone.offsets.abc123", 500)
            raw = store.raw_snapshot()
            assert raw["owntone"]["offsets"]["abc123"] == 500
            # A second output's offset must not clobber the first.
            store.set("owntone.offsets.def456", -1500)
            raw = store.raw_snapshot()
            assert raw["owntone"]["offsets"]["abc123"] == 500
            assert raw["owntone"]["offsets"]["def456"] == -1500
        finally:
            store.close(save=False)
