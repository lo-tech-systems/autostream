"""test_render_license_md.py — unit tests for render_license_md().

render_license_md() is a small Markdown-to-HTML converter used to render
LICENSE text and (soon) GitHub release notes. Its output is injected into
the page via innerHTML, so escaping of user/upstream-controlled text is
security-relevant and is tested explicitly here.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_webui_common import render_license_md


class TestHeadings:
    def test_h1_becomes_h2(self):
        assert render_license_md("# Title") == "<h2>Title</h2>"

    def test_h2_becomes_h3(self):
        assert render_license_md("## Title") == "<h3>Title</h3>"

    def test_h3_becomes_h4(self):
        assert render_license_md("### Title") == "<h4>Title</h4>"


class TestHorizontalRule:
    def test_hr(self):
        assert render_license_md("---") == "<hr>"

    def test_hr_between_paragraphs(self):
        out = render_license_md("above\n---\nbelow")
        assert out == "<p>above</p>\n<hr>\n<p>below</p>"


class TestBullets:
    def test_dash_bullet(self):
        assert render_license_md("- item") == "<ul>\n<li>item</li>\n</ul>"

    def test_star_bullet(self):
        assert render_license_md("* item") == "<ul>\n<li>item</li>\n</ul>"

    def test_multiple_consecutive_items_one_ul(self):
        out = render_license_md("- one\n- two\n- three")
        assert out == "<ul>\n<li>one</li>\n<li>two</li>\n<li>three</li>\n</ul>"

    def test_list_closed_by_blank_line(self):
        out = render_license_md("- one\n\nafter")
        assert out == "<ul>\n<li>one</li>\n</ul>\n<p>after</p>"

    def test_list_closed_by_heading(self):
        out = render_license_md("- one\n## Next")
        assert out == "<ul>\n<li>one</li>\n</ul>\n<h3>Next</h3>"


class TestParagraphs:
    def test_consecutive_lines_joined_with_space(self):
        out = render_license_md("line one\nline two")
        assert out == "<p>line one line two</p>"

    def test_blank_line_starts_new_paragraph(self):
        out = render_license_md("first para\n\nsecond para")
        assert out == "<p>first para</p>\n<p>second para</p>"


class TestBlockquote:
    def test_simple_blockquote(self):
        out = render_license_md("> quoted text")
        assert out == "<blockquote><p>quoted text</p></blockquote>"

    def test_multiline_blockquote(self):
        out = render_license_md("> line one\n> line two")
        assert out == "<blockquote><p>line one line two</p></blockquote>"

    def test_blockquote_renders_inner_markdown_recursively(self):
        out = render_license_md("> ## Heading\n> - item")
        assert out == (
            "<blockquote><h3>Heading</h3>\n<ul>\n<li>item</li>\n</ul></blockquote>"
        )


class TestInlineFormatting:
    def test_bold(self):
        assert render_license_md("**bold**") == "<p><strong>bold</strong></p>"

    def test_italic(self):
        assert render_license_md("*italic*") == "<p><em>italic</em></p>"

    def test_bold_and_italic_inside_bullet(self):
        out = render_license_md("- **bold** and *italic*")
        assert out == "<ul>\n<li><strong>bold</strong> and <em>italic</em></li>\n</ul>"


class TestAutolink:
    def test_bare_url_autolinked(self):
        out = render_license_md("See https://example.com/path for details")
        assert (
            '<a href="https://example.com/path" target="_blank" '
            'rel="noopener noreferrer">https://example.com/path</a>' in out
        )
        assert out.startswith("<p>See ")
        assert out.endswith(" for details</p>")


class TestEscaping:
    def test_script_tag_is_escaped(self):
        out = render_license_md("<script>alert(1)</script>")
        assert "<script>" not in out
        assert "</script>" not in out
        assert "&lt;script&gt;" in out
        assert "&lt;/script&gt;" in out

    def test_img_onerror_payload_is_escaped(self):
        payload = '<img src=x onerror="alert(1)">'
        out = render_license_md(payload)
        assert "<img" not in out
        assert "&lt;img" in out
        assert "&quot;alert(1)&quot;" in out or "alert(1)" in out

    def test_ampersand_is_escaped(self):
        out = render_license_md("Tom & Jerry")
        assert "&amp;" in out
        assert " & " not in out

    def test_no_raw_angle_brackets_survive_from_input(self):
        malicious = "<b onclick=\"evil()\">click</b>"
        out = render_license_md(malicious)
        # The only '<' and '>' characters in the output must belong to the
        # tags render_license_md itself generates (<p> and </p> here), never
        # to raw input.
        stripped = out.replace("<p>", "").replace("</p>", "")
        assert "<" not in stripped
        assert ">" not in stripped

    def test_escaping_applied_inside_bullet(self):
        out = render_license_md("- <script>alert(1)</script>")
        assert "<script>" not in out
        assert "&lt;script&gt;" in out

    def test_escaping_applied_inside_heading(self):
        out = render_license_md("# <script>alert(1)</script>")
        assert "<script>" not in out
        assert out == "<h2>&lt;script&gt;alert(1)&lt;/script&gt;</h2>"

    def test_escaping_applied_inside_blockquote(self):
        out = render_license_md("> <script>alert(1)</script>")
        assert "<script>" not in out
        assert "&lt;script&gt;" in out


class TestMarkdownLinkNotConverted:
    def test_markdown_link_syntax_not_recognised_as_a_link(self):
        # Documents current behaviour: [text](url) markdown-link syntax is
        # not specifically recognised. The leading "[text](" is left as
        # plain text; the bare-URL autolinker still matches the URL run
        # inside the parens (including the trailing ")"), since it has no
        # concept of markdown-link syntax.
        out = render_license_md("[click here](https://example.com)")
        assert "[click here](" in out
        assert '<a href="https://example.com)"' in out


class TestEdgeCases:
    def test_empty_string(self):
        assert render_license_md("") == ""


class TestReleaseNotesShape:
    def test_heading_then_bullets(self):
        text = "## What's Changed\n\n- Fix A\n- Fix B\n- Fix C"
        out = render_license_md(text)
        # html.escape() also escapes the apostrophe to &#x27;.
        assert out == (
            "<h3>What&#x27;s Changed</h3>\n"
            "<ul>\n<li>Fix A</li>\n<li>Fix B</li>\n<li>Fix C</li>\n</ul>"
        )
        assert out.count("<ul>") == 1
        assert out.count("<li>") == 3
