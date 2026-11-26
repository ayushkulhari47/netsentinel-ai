"""Optional AbuseIPDB threat-intelligence lookup service with TTL caching."""

from datetime import datetime, timezone
import ipaddress
import numbers
import os
import time
import requests

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT_SECONDS = 5
DEFAULT_CACHE_TTL_SECONDS = 900

PLACEHOLDER_KEYS = {
    "",
    "your-abuseipdb-api-key-here",
    "changeme",
    "replace-me",
}

ABUSEIPDB_CATEGORY_NAMES = {
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def _utc_iso_now(epoch_seconds):
    """Format epoch seconds as an ISO-8601 UTC timestamp string."""
    return datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc).isoformat()


def _is_non_public_ip(ip_obj):
    """Return True if IP is private, loopback, reserved, link-local, multicast, or unspecified."""
    return bool(
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_reserved
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    )


def _normalize_api_key(raw_key):
    """Return stripped API key if configured, or None if missing/placeholder."""
    if not isinstance(raw_key, str):
        return None
    cleaned = raw_key.strip()
    if cleaned.lower() in PLACEHOLDER_KEYS:
        return None
    return cleaned


def _extract_categories(data):
    """Extract sorted unique human-readable category labels from AbuseIPDB response data."""
    category_ids = set()

    raw_categories = data.get("categories")
    if isinstance(raw_categories, list):
        for item in raw_categories:
            if isinstance(item, int) and not isinstance(item, bool):
                category_ids.add(item)

    reports = data.get("reports")
    if isinstance(reports, list):
        for report in reports:
            if not isinstance(report, dict):
                continue
            cats = report.get("categories")
            if isinstance(cats, list):
                for item in cats:
                    if isinstance(item, int) and not isinstance(item, bool):
                        category_ids.add(item)

    return [
        ABUSEIPDB_CATEGORY_NAMES.get(cat_id, f"Category {cat_id}")
        for cat_id in sorted(category_ids)
    ]


def _classify_abuse_score(abuse_score):
    """Map AbuseIPDB abuseConfidenceScore (0-100) to reputation, confidence, and summary."""
    if abuse_score >= 75:
        reputation = "reported"
        confidence = round(abuse_score / 100.0, 4)
        summary = (
            f"Reported by the provider (AbuseIPDB) with an abuse score of "
            f"{abuse_score:.0f}/100."
        )
    elif abuse_score >= 1:
        reputation = "suspicious"
        confidence = round(abuse_score / 100.0, 4)
        summary = (
            f"Flagged as potentially suspicious by the provider (AbuseIPDB) with an "
            f"abuse score of {abuse_score:.0f}/100."
        )
    else:
        reputation = "clean"
        confidence = 0.8
        summary = "No abuse reports currently indicated by the provider (AbuseIPDB)."

    return reputation, confidence, summary


class ThreatIntelService:
    """Queries optional AbuseIPDB reputation data with strict safety and TTL caching."""

    def __init__(
        self,
        api_key=None,
        cache_ttl_seconds=DEFAULT_CACHE_TTL_SECONDS,
        timeout_seconds=REQUEST_TIMEOUT_SECONDS,
        time_fn=None,
        http_get=None,
    ):
        """Configure the service without making any network requests at startup."""
        self._explicit_api_key = api_key
        self.cache_ttl_seconds = max(0.0, float(cache_ttl_seconds))
        self.timeout_seconds = float(timeout_seconds)
        self._time_fn = time_fn if time_fn is not None else time.time
        self._http_get = http_get
        self._cache = {}

    def _get_api_key(self):
        """Resolve ABUSEIPDB_API_KEY from explicit config or environment."""
        raw = self._explicit_api_key if self._explicit_api_key is not None else os.environ.get("ABUSEIPDB_API_KEY")
        return _normalize_api_key(raw)

    def clear_cache(self):
        """Clear all cached IP lookup entries."""
        self._cache.clear()

    def _build_result(
        self,
        ip_str,
        reputation,
        confidence,
        provider,
        abuse_score,
        categories,
        checked_at,
        summary,
        cached=False,
    ):
        """Build a standardized threat-intel response dictionary without secrets."""
        return {
            "ip": ip_str,
            "reputation": reputation,
            "confidence": confidence,
            "provider": provider,
            "abuse_score": abuse_score,
            "categories": categories,
            "checked_at": checked_at,
            "cached": cached,
            "summary": summary,
        }

    def lookup_ip(self, ip_address):
        """Look up reputation for an IP address, respecting privacy, missing keys, and TTL cache."""
        if not isinstance(ip_address, str) or not ip_address.strip():
            raise ValueError("Invalid IP address.")

        try:
            ip_obj = ipaddress.ip_address(ip_address.strip())
        except ValueError as exc:
            raise ValueError("Invalid IP address.") from exc

        normalized_ip = str(ip_obj)
        now = float(self._time_fn())
        checked_at = _utc_iso_now(now)

        # 1. Never query private, loopback, or reserved IP addresses externally.
        if _is_non_public_ip(ip_obj):
            return self._build_result(
                ip_str=normalized_ip,
                reputation="private",
                confidence=0.0,
                provider="local",
                abuse_score=0,
                categories=[],
                checked_at=checked_at,
                summary="Private, loopback, or reserved IP address; external lookup skipped.",
                cached=False,
            )

        # 2. Return valid cached result if within TTL.
        cached_entry = self._cache.get(normalized_ip)
        if cached_entry is not None:
            expires_at, stored_result = cached_entry
            if now < expires_at:
                result_copy = dict(stored_result)
                result_copy["cached"] = True
                return result_copy
            del self._cache[normalized_ip]

        # 3. Never call any external API when ABUSEIPDB_API_KEY is missing.
        api_key = self._get_api_key()
        if api_key is None:
            return self._build_result(
                ip_str=normalized_ip,
                reputation="unknown",
                confidence=0.0,
                provider="abuseipdb",
                abuse_score=0,
                categories=[],
                checked_at=checked_at,
                summary="AbuseIPDB API key is not configured; external lookup skipped.",
                cached=False,
            )

        # 4. Query AbuseIPDB safely with 5-second timeout.
        http_get = self._http_get if self._http_get is not None else requests.get
        headers = {
            "Key": api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": normalized_ip,
            "maxAgeInDays": 90,
            "verbose": "",
        }

        try:
            response = http_get(
                ABUSEIPDB_CHECK_URL,
                headers=headers,
                params=params,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException:
            return self._build_result(
                ip_str=normalized_ip,
                reputation="unknown",
                confidence=0.0,
                provider="abuseipdb",
                abuse_score=0,
                categories=[],
                checked_at=checked_at,
                summary="Provider lookup failed due to a network or timeout error.",
                cached=False,
            )

        status_code = getattr(response, "status_code", None)
        if status_code == 429:
            return self._build_result(
                ip_str=normalized_ip,
                reputation="unknown",
                confidence=0.0,
                provider="abuseipdb",
                abuse_score=0,
                categories=[],
                checked_at=checked_at,
                summary="Provider lookup was rate-limited; returning unknown reputation.",
                cached=False,
            )

        if status_code != 200:
            return self._build_result(
                ip_str=normalized_ip,
                reputation="unknown",
                confidence=0.0,
                provider="abuseipdb",
                abuse_score=0,
                categories=[],
                checked_at=checked_at,
                summary="Provider returned an unsuccessful response; returning unknown reputation.",
                cached=False,
            )

        try:
            payload = response.json()
        except ValueError:
            return self._build_result(
                ip_str=normalized_ip,
                reputation="unknown",
                confidence=0.0,
                provider="abuseipdb",
                abuse_score=0,
                categories=[],
                checked_at=checked_at,
                summary="Provider returned invalid JSON; returning unknown reputation.",
                cached=False,
            )

        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            return self._build_result(
                ip_str=normalized_ip,
                reputation="unknown",
                confidence=0.0,
                provider="abuseipdb",
                abuse_score=0,
                categories=[],
                checked_at=checked_at,
                summary="Provider response was missing expected data fields.",
                cached=False,
            )

        raw_score = data.get("abuseConfidenceScore")
        if not isinstance(raw_score, numbers.Real) or isinstance(raw_score, bool):
            return self._build_result(
                ip_str=normalized_ip,
                reputation="unknown",
                confidence=0.0,
                provider="abuseipdb",
                abuse_score=0,
                categories=[],
                checked_at=checked_at,
                summary="Provider response contained an invalid abuse score.",
                cached=False,
            )

        abuse_score = max(0, min(100, int(round(float(raw_score)))))
        categories = _extract_categories(data)
        reputation, confidence, summary = _classify_abuse_score(abuse_score)

        result = self._build_result(
            ip_str=normalized_ip,
            reputation=reputation,
            confidence=confidence,
            provider="abuseipdb",
            abuse_score=abuse_score,
            categories=categories,
            checked_at=checked_at,
            summary=summary,
            cached=False,
        )

        if self.cache_ttl_seconds > 0.0:
            self._cache[normalized_ip] = (now + self.cache_ttl_seconds, dict(result))

        return result
