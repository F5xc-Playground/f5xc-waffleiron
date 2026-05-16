"""ServicePolicyTranslator: converts AsmPolicy → XC service_policy dict.

Handles IP whitelists, geolocation blocks, and IP intelligence threat categories.
Returns None when none of these features are configured.
"""

from __future__ import annotations

import ipaddress

from waffleiron.model import AsmPolicy
from waffleiron.translators.mappings import ASM_IP_INTEL_TO_XC
from waffleiron.translators.utils import sanitize_xc_name

# ---------------------------------------------------------------------------
# Country name → ISO 3166-1 alpha-2 code mapping
# ---------------------------------------------------------------------------

_COUNTRY_NAME_TO_CODE: dict[str, str] = {
    "Afghanistan": "AF",
    "Albania": "AL",
    "Algeria": "DZ",
    "Angola": "AO",
    "Argentina": "AR",
    "Armenia": "AM",
    "Australia": "AU",
    "Austria": "AT",
    "Azerbaijan": "AZ",
    "Bahrain": "BH",
    "Bangladesh": "BD",
    "Belarus": "BY",
    "Belgium": "BE",
    "Bolivia": "BO",
    "Bosnia and Herzegovina": "BA",
    "Brazil": "BR",
    "Bulgaria": "BG",
    "Cambodia": "KH",
    "Cameroon": "CM",
    "Canada": "CA",
    "Chile": "CL",
    "China": "CN",
    "Colombia": "CO",
    "Congo": "CG",
    "Costa Rica": "CR",
    "Croatia": "HR",
    "Cuba": "CU",
    "Cyprus": "CY",
    "Czech Republic": "CZ",
    "Denmark": "DK",
    "Dominican Republic": "DO",
    "Ecuador": "EC",
    "Egypt": "EG",
    "El Salvador": "SV",
    "Estonia": "EE",
    "Ethiopia": "ET",
    "Finland": "FI",
    "France": "FR",
    "Georgia": "GE",
    "Germany": "DE",
    "Ghana": "GH",
    "Greece": "GR",
    "Guatemala": "GT",
    "Honduras": "HN",
    "Hong Kong": "HK",
    "Hungary": "HU",
    "Iceland": "IS",
    "India": "IN",
    "Indonesia": "ID",
    "Iran": "IR",
    "Iraq": "IQ",
    "Ireland": "IE",
    "Israel": "IL",
    "Italy": "IT",
    "Jamaica": "JM",
    "Japan": "JP",
    "Jordan": "JO",
    "Kazakhstan": "KZ",
    "Kenya": "KE",
    "Kuwait": "KW",
    "Kyrgyzstan": "KG",
    "Latvia": "LV",
    "Lebanon": "LB",
    "Libya": "LY",
    "Lithuania": "LT",
    "Luxembourg": "LU",
    "Malaysia": "MY",
    "Mexico": "MX",
    "Moldova": "MD",
    "Mongolia": "MN",
    "Morocco": "MA",
    "Mozambique": "MZ",
    "Myanmar": "MM",
    "Nepal": "NP",
    "Netherlands": "NL",
    "New Zealand": "NZ",
    "Nicaragua": "NI",
    "Nigeria": "NG",
    "North Korea": "KP",
    "Norway": "NO",
    "Oman": "OM",
    "Pakistan": "PK",
    "Panama": "PA",
    "Paraguay": "PY",
    "Peru": "PE",
    "Philippines": "PH",
    "Poland": "PL",
    "Portugal": "PT",
    "Qatar": "QA",
    "Romania": "RO",
    "Russia": "RU",
    "Saudi Arabia": "SA",
    "Serbia": "RS",
    "Singapore": "SG",
    "Slovakia": "SK",
    "Slovenia": "SI",
    "Somalia": "SO",
    "South Africa": "ZA",
    "South Korea": "KR",
    "Spain": "ES",
    "Sri Lanka": "LK",
    "Sudan": "SD",
    "Sweden": "SE",
    "Switzerland": "CH",
    "Syria": "SY",
    "Taiwan": "TW",
    "Tajikistan": "TJ",
    "Tanzania": "TZ",
    "Thailand": "TH",
    "Tunisia": "TN",
    "Turkey": "TR",
    "Turkmenistan": "TM",
    "Uganda": "UG",
    "Ukraine": "UA",
    "United Arab Emirates": "AE",
    "United Kingdom": "GB",
    "United States": "US",
    "Uruguay": "UY",
    "Uzbekistan": "UZ",
    "Venezuela": "VE",
    "Vietnam": "VN",
    "Yemen": "YE",
    "Zimbabwe": "ZW",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mask_to_prefix_len(mask: str) -> int:
    """Convert a dotted-decimal subnet mask to a CIDR prefix length.

    Uses the stdlib ipaddress module for correctness.
    """
    # Pack the mask as though it were an IP and count set bits
    packed = ipaddress.ip_address(mask).packed
    bits = 0
    for byte in packed:
        bits += bin(byte).count("1")
    return bits


def _ip_to_cidr(ip: str, mask: str) -> str:
    """Return the CIDR notation for an IP + subnet mask pair."""
    prefix_len = _mask_to_prefix_len(mask)
    return f"{ip}/{prefix_len}"


def _rule_name_for_ip(cidr: str) -> str:
    """Build an XC-safe rule name for an IP allow rule."""
    # Replace dots and slashes with hyphens, e.g. "10.0.0.0/8" → "10-0-0-0-8"
    slug = cidr.replace(".", "-").replace("/", "-")
    return sanitize_xc_name(f"allow-ip-{slug}")


def _rule_name_for_country(country_name: str) -> str:
    """Build an XC-safe rule name for a geo deny rule."""
    return sanitize_xc_name(f"deny-geo-{country_name}")


def _rule_name_for_threat(category_name: str) -> str:
    """Build an XC-safe rule name for an IP intelligence deny rule."""
    return sanitize_xc_name(f"deny-threat-{category_name}")


# ---------------------------------------------------------------------------
# ServicePolicyTranslator
# ---------------------------------------------------------------------------


class ServicePolicyTranslator:
    """Translates an AsmPolicy to an XC service_policy CreateSpec dict.

    Returns None when none of IP whitelist, geolocation, or IP intelligence
    features are configured.
    """

    @staticmethod
    def translate(policy: AsmPolicy, namespace: str, name_override: str | None = None) -> dict | None:
        """Build the XC service_policy JSON object.

        Args:
            policy: Populated AsmPolicy intermediate model.
            namespace: Target F5 XC namespace.
            name_override: Optional name to use instead of policy.name.

        Returns:
            A dict matching the XC service_policy CreateSpec JSON structure,
            or None if no relevant features are configured.
        """
        rules: list[dict] = []

        # --- 1. IP allow rules (from whitelist_ips) ---
        for entry in policy.whitelist_ips:
            cidr = _ip_to_cidr(entry.ip, entry.mask)
            rule = {
                "metadata": {"name": _rule_name_for_ip(cidr)},
                "spec": {
                    "action": "ALLOW",
                    "any_client": {},
                    "ip_prefix_list": {
                        "ip_prefixes": [cidr],
                    },
                    "waf_action": {"none": {}},
                },
            }
            rules.append(rule)

        # --- 2. Geo deny rules (from geolocation.disallowed) ---
        geo_codes = []
        for country_name in policy.geolocation.disallowed:
            code = _COUNTRY_NAME_TO_CODE.get(country_name)
            if code is not None:
                geo_codes.append(code)
        if geo_codes:
            codes_str = ", ".join(geo_codes)
            rule = {
                "metadata": {"name": sanitize_xc_name("deny-geo-blocked-countries")},
                "spec": {
                    "action": "DENY",
                    "client_selector": {
                        "expressions": [f"country in ({codes_str})"],
                    },
                    "waf_action": {"none": {}},
                },
            }
            rules.append(rule)

        # --- 3. IP intelligence / threat category rules ---
        for category in policy.ip_intelligence.categories:
            xc_category = ASM_IP_INTEL_TO_XC.get(category.name)
            if xc_category is None:
                continue
            rule = {
                "metadata": {"name": _rule_name_for_threat(category.name)},
                "spec": {
                    "action": "DENY",
                    "any_client": {},
                    "ip_threat_category_list": {
                        "ip_threat_categories": [xc_category],
                    },
                    "waf_action": {"none": {}},
                },
            }
            rules.append(rule)

        if not rules:
            return None

        suffix = "-svc"
        base = sanitize_xc_name(name_override or policy.name)[:64 - len(suffix)].rstrip("-")
        policy_name = base + suffix

        return {
            "metadata": {
                "name": policy_name,
                "namespace": namespace,
            },
            "spec": {
                "rule_list": {
                    "rules": rules,
                },
            },
        }
