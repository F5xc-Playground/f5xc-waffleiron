"""Shared AWAF-to-XC mapping constants used by all translators."""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Signature-set name  →  XC attack-type enum
# ---------------------------------------------------------------------------
ASM_SIG_SET_TO_XC_ATTACK_TYPE: dict[str, str] = {
    "SQL Injection Signatures": "ATTACK_TYPE_SQL_INJECTION",
    "Cross-Site Scripting Signatures": "ATTACK_TYPE_CROSS_SITE_SCRIPTING",
    "OS Command Injection Signatures": "ATTACK_TYPE_COMMAND_EXECUTION",
    "Path Traversal Signatures": "ATTACK_TYPE_PATH_TRAVERSAL",
    "XPath Injection Signatures": "ATTACK_TYPE_XPATH_INJECTION",
    "LDAP Injection Signatures": "ATTACK_TYPE_LDAP_INJECTION",
    "Server Side Code Injection Signatures": "ATTACK_TYPE_SERVER_SIDE_CODE_INJECTION",
    "Buffer Overflow Signatures": "ATTACK_TYPE_BUFFER_OVERFLOW",
    "Information Leakage Signatures": "ATTACK_TYPE_INFORMATION_LEAKAGE",
    "Directory Indexing Signatures": "ATTACK_TYPE_DIRECTORY_INDEXING",
    "Remote File Include Signatures": "ATTACK_TYPE_REMOTE_FILE_INCLUDE",
    "Vulnerability Scanner Signatures": "ATTACK_TYPE_VULNERABILITY_SCAN",
    "Trojan/Backdoor/Spyware Signatures": "ATTACK_TYPE_TROJAN_BACKDOOR_SPYWARE",
    "Authentication/Authorization Signatures": "ATTACK_TYPE_AUTHENTICATION_AUTHORIZATION_ATTACKS",
    "Denial of Service Signatures": "ATTACK_TYPE_DENIAL_OF_SERVICE",
    "Predictable Resource Location Signatures": "ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION",
    "Abuse of Functionality Signatures": "ATTACK_TYPE_ABUSE_OF_FUNCTIONALITY",
    "HTTP Response Splitting Signatures": "ATTACK_TYPE_HTTP_RESPONSE_SPLITTING",
    "Detection Evasion Signatures": "ATTACK_TYPE_DETECTION_EVASION",
    "Non-Browser Client Signatures": "ATTACK_TYPE_NON_BROWSER_CLIENT",
    "Other Application Attacks Signatures": "ATTACK_TYPE_OTHER_APPLICATION_ATTACKS",
}

# ---------------------------------------------------------------------------
# AWAF evasion violation  →  XC evasion sub-types
# ---------------------------------------------------------------------------
ASM_EVASION_XC_SUBTYPES: list[str] = [
    "VIOL_EVASION_DIRECTORY_TRAVERSALS",
    "VIOL_EVASION_MULTIPLE_DECODING",
    "VIOL_EVASION_APACHE_WHITESPACE",
    "VIOL_EVASION_IIS_UNICODE_CODEPOINTS",
    "VIOL_EVASION_IIS_BACKSLASHES",
    "VIOL_EVASION_PERCENT_U_DECODING",
    "VIOL_EVASION_BARE_BYTE_DECODING",
    "VIOL_EVASION_BAD_UNESCAPE",
]

# ---------------------------------------------------------------------------
# AWAF HTTP-protocol violation  →  XC HTTP-protocol sub-types
# ---------------------------------------------------------------------------
ASM_HTTP_PROTOCOL_XC_SUBTYPES: list[str] = [
    "VIOL_HTTP_PROTOCOL_MULTIPLE_HOST_HEADERS",
    "VIOL_HTTP_PROTOCOL_BAD_HOST_HEADER_VALUE",
    "VIOL_HTTP_PROTOCOL_UNPARSABLE_REQUEST_CONTENT",
    "VIOL_HTTP_PROTOCOL_NULL_IN_REQUEST",
    "VIOL_HTTP_PROTOCOL_BAD_HTTP_VERSION",
    "VIOL_HTTP_PROTOCOL_CRLF_CHARACTERS_BEFORE_REQUEST_START",
    "VIOL_HTTP_PROTOCOL_NO_HOST_HEADER_IN_HTTP_1_1_REQUEST",
    "VIOL_HTTP_PROTOCOL_BAD_MULTIPART_PARAMETERS_PARSING",
    "VIOL_HTTP_PROTOCOL_SEVERAL_CONTENT_LENGTH_HEADERS",
    "VIOL_HTTP_PROTOCOL_CONTENT_LENGTH_SHOULD_BE_A_POSITIVE_NUMBER",
]

# ---------------------------------------------------------------------------
# AWAF violation name  →  list of XC violation equivalents
# ---------------------------------------------------------------------------
ASM_VIOLATION_TO_XC_VIOLATIONS: dict[str, list[str]] = {
    "VIOL_FILETYPE": ["VIOL_FILETYPE"],
    "VIOL_METHOD": ["VIOL_METHOD"],
    "VIOL_REQUEST_MAX_LENGTH": ["VIOL_REQUEST_MAX_LENGTH"],
    "VIOL_DATA_GUARD": ["VIOL_DATA_GUARD"],
    "VIOL_COOKIE_MODIFIED": ["VIOL_COOKIE_MODIFIED"],
    "VIOL_ASM_COOKIE_MODIFIED": ["VIOL_ASM_COOKIE_MODIFIED"],
    "VIOL_ENCODING": ["VIOL_ENCODING"],
    "VIOL_XML_FORMAT": ["VIOL_XML_MALFORMED"],
    "VIOL_JSON_FORMAT": ["VIOL_JSON_MALFORMED"],
    "VIOL_FILE_UPLOAD": ["VIOL_FILE_UPLOAD"],
    "VIOL_MANDATORY_HEADER": ["VIOL_MANDATORY_HEADER"],
    "VIOL_EVASION": ASM_EVASION_XC_SUBTYPES,
    "VIOL_HTTP_PROTOCOL": ASM_HTTP_PROTOCOL_XC_SUBTYPES,
}

# ---------------------------------------------------------------------------
# AWAF bot category  →  XC bot-defence action key
# ---------------------------------------------------------------------------
ASM_BOT_CATEGORY_TO_XC: dict[str, str] = {
    "malicious-bot": "malicious_bot_action",
    "benign-bot": "good_bot_action",
    "unknown-bot": "suspicious_bot_action",
}


# ---------------------------------------------------------------------------
# AWAF IP Intelligence category → XC IPThreatCategory enum
# ---------------------------------------------------------------------------
ASM_IP_INTEL_TO_XC: dict[str, str] = {
    "botnets": "BOTNETS",
    "scanners": "SCANNERS",
    "spam_sources": "SPAM_SOURCES",
    "spam-sources": "SPAM_SOURCES",
    "phishing": "PHISHING",
    "denial_of_service": "DENIAL_OF_SERVICE",
    "denial-of-service": "DENIAL_OF_SERVICE",
    "windows_exploits": "WINDOWS_EXPLOITS",
    "windows-exploits": "WINDOWS_EXPLOITS",
    "web_attacks": "WEB_ATTACKS",
    "web-attacks": "WEB_ATTACKS",
    "proxy": "PROXY",
    "tor_proxy": "TOR_PROXY",
    "tor-proxy": "TOR_PROXY",
    "mobile_threats": "MOBILE_THREATS",
    "mobile-threats": "MOBILE_THREATS",
    "infected_sources": "REPUTATION",
    "infected-sources": "REPUTATION",
}

# All valid XC IPThreatCategory enum values (from ves.io.schema.policy protobuf)
XC_IP_THREAT_CATEGORIES: frozenset[str] = frozenset({
    "SPAM_SOURCES",
    "WINDOWS_EXPLOITS",
    "WEB_ATTACKS",
    "BOTNETS",
    "SCANNERS",
    "REPUTATION",
    "PHISHING",
    "PROXY",
    "MOBILE_THREATS",
    "TOR_PROXY",
    "DENIAL_OF_SERVICE",
    "NETWORK",
})


# ---------------------------------------------------------------------------
# Blocking-page template variable translation
# ---------------------------------------------------------------------------
import re

_AWAF_VAR_PATTERN = re.compile(r"<%[^%]+%>")
_SUPPORTED_AWAF_VARS = frozenset({"<%TS.request.ID()%>"})


def translate_blocking_page_vars(html: str) -> str:
    """Replace AWAF blocking-page template variables with XC equivalents."""
    return html.replace("<%TS.request.ID()%>", "{{request_id}}")


def find_unsupported_blocking_page_vars(html: str) -> list[str]:
    """Return any AWAF template variables that have no XC equivalent."""
    all_vars = set(_AWAF_VAR_PATTERN.findall(html))
    return sorted(all_vars - _SUPPORTED_AWAF_VARS)
