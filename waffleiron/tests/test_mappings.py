"""Tests for shared ASM-to-XC mapping constants."""

from waffleiron.translators.mappings import (
    ASM_SIG_SET_TO_XC_ATTACK_TYPE,
    ASM_VIOLATION_TO_XC_VIOLATIONS,
    ASM_EVASION_XC_SUBTYPES,
    ASM_HTTP_PROTOCOL_XC_SUBTYPES,
    ASM_BOT_CATEGORY_TO_XC,
    translate_blocking_page_vars,
)


def test_sig_set_mapping_covers_all_xc_attack_types():
    xc_types = set(ASM_SIG_SET_TO_XC_ATTACK_TYPE.values())
    assert "ATTACK_TYPE_SQL_INJECTION" in xc_types
    assert "ATTACK_TYPE_CROSS_SITE_SCRIPTING" in xc_types
    assert "ATTACK_TYPE_COMMAND_EXECUTION" in xc_types
    assert "ATTACK_TYPE_PATH_TRAVERSAL" in xc_types
    assert len(xc_types) >= 20


def test_evasion_subtypes():
    assert len(ASM_EVASION_XC_SUBTYPES) == 8
    assert all(v.startswith("VIOL_EVASION_") for v in ASM_EVASION_XC_SUBTYPES)


def test_http_protocol_subtypes():
    assert len(ASM_HTTP_PROTOCOL_XC_SUBTYPES) == 10
    assert all(v.startswith("VIOL_HTTP_PROTOCOL_") for v in ASM_HTTP_PROTOCOL_XC_SUBTYPES)


def test_blocking_page_variable_translation():
    html = "<p>Request ID: <%TS.request.ID()%></p>"
    result = translate_blocking_page_vars(html)
    assert result == "<p>Request ID: {{request_id}}</p>"


def test_blocking_page_no_change():
    html = "<p>Blocked</p>"
    assert translate_blocking_page_vars(html) == html


def test_bot_category_mapping():
    assert ASM_BOT_CATEGORY_TO_XC["malicious-bot"] == "malicious_bot_action"
    assert ASM_BOT_CATEGORY_TO_XC["benign-bot"] == "good_bot_action"
    assert ASM_BOT_CATEGORY_TO_XC["unknown-bot"] == "suspicious_bot_action"


def test_violation_mapping_direct():
    assert "VIOL_FILETYPE" in ASM_VIOLATION_TO_XC_VIOLATIONS
    assert ASM_VIOLATION_TO_XC_VIOLATIONS["VIOL_FILETYPE"] == ["VIOL_FILETYPE"]


def test_violation_mapping_split():
    # VIOL_EVASION maps to 8 sub-types
    assert "VIOL_EVASION" in ASM_VIOLATION_TO_XC_VIOLATIONS
    assert len(ASM_VIOLATION_TO_XC_VIOLATIONS["VIOL_EVASION"]) == 8
    # VIOL_HTTP_PROTOCOL maps to 10 sub-types
    assert "VIOL_HTTP_PROTOCOL" in ASM_VIOLATION_TO_XC_VIOLATIONS
    assert len(ASM_VIOLATION_TO_XC_VIOLATIONS["VIOL_HTTP_PROTOCOL"]) == 10
