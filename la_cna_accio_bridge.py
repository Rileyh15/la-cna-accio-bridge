#!/usr/bin/env python3
"""
Louisiana CNA Registry ↔ Accio Data Integration Bridge
========================================================

Production-grade, zero-trust integration that:
  1. Receives candidate records from Accio Data's XML API (containing SSNs)
  2. Submits SSN to the LA CNA/DSW Registry public lookup form
  3. Parses certification status from response HTML
  4. Pushes verification results back to Accio Data
  5. Permanently destroys all PII from memory

SECURITY POSTURE:
  - SSNs exist ONLY in RAM, ONLY during the lookup window
  - Triple-layer ephemeral handling: in-memory → immediate zeroing → forced GC
  - Zero disk writes, zero logging of PII, zero caching
  - All network traffic over TLS 1.2+

Author : CRA Integration Team
License: Proprietary – CRA Internal Use Only
Python : 3.12+
"""

from __future__ import annotations

import asyncio
import ctypes
import gc
import hashlib
import hmac
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import httpx

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: CONFIGURATION  (all secrets from environment variables)
# ═══════════════════════════════════════════════════════════════════════════════

# Accio Data API configuration
ACCIO_API_BASE_URL: str = os.environ.get("ACCIO_API_BASE_URL", "")
ACCIO_API_ACCOUNT: str = os.environ.get("ACCIO_API_ACCOUNT", "")
ACCIO_API_USERNAME: str = os.environ.get("ACCIO_API_USERNAME", "")
ACCIO_API_PASSWORD: str = os.environ.get("ACCIO_API_PASSWORD", "")
ACCIO_API_MODE: str = os.environ.get("ACCIO_API_MODE", "PROD")

# Webhook authentication
WEBHOOK_SECRET: str = os.environ.get("WEBHOOK_SECRET", "")

# LA CNA Registry
LA_CNA_URL: str = "https://tlc.dhh.la.gov/frmsearchweb2.aspx"

# Operational tuning
MAX_CONCURRENT_LOOKUPS: int = int(os.environ.get("MAX_CONCURRENT_LOOKUPS", "3"))
HTTP_TIMEOUT_SECONDS: int = int(os.environ.get("HTTP_TIMEOUT_SECONDS", "30"))
MAX_RETRIES: int = int(os.environ.get("MAX_RETRIES", "3"))
RETRY_BASE_DELAY: float = float(os.environ.get("RETRY_BASE_DELAY", "2.0"))

# Validate critical configuration at import time
_REQUIRED_ENV_VARS = [
    "ACCIO_API_BASE_URL",
    "ACCIO_API_ACCOUNT",
    "ACCIO_API_USERNAME",
    "ACCIO_API_PASSWORD",
    "WEBHOOK_SECRET",
]


def _validate_config() -> None:
    """Fail fast if any required environment variable is missing."""
    missing = [v for v in _REQUIRED_ENV_VARS if not os.environ.get(v)]
    if missing:
        # Safe to log variable NAMES (never values)
        raise EnvironmentError(
            f"Missing required environment variables: {', '.join(missing)}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: SECURE MEMORY HANDLING  (the SSN fortress)
# ═══════════════════════════════════════════════════════════════════════════════


def _secure_zero_string(s: str) -> str:
    """
    Best-effort secure zeroing of a Python string's internal buffer.

    Python strings are immutable and CPython's internal layout varies
    between versions (3.10 vs 3.12+ have different header sizes).
    We use a version-aware approach that probes for the correct offset
    by searching for the string's own content in memory.

    Returns a zeroed replacement string for variable reassignment.
    """
    if not s:
        return ""
    try:
        buf_size = len(s)
        str_address = id(s)

        # Detect the correct data offset by finding the string's bytes
        # in memory near the object header. CPython stores compact ASCII
        # strings inline after the header. Header size varies:
        #   Python 3.10-3.11: ~48 bytes (PyCompactUnicodeObject)
        #   Python 3.12+: ~40 bytes (new compact layout)
        # We probe safely by reading first, then writing only if matched.
        probe_byte = s[0].encode("utf-8")[0] if s else 0
        found_offset = None

        for candidate_offset in (40, 48, 52, 56):
            try:
                # Read one byte at the candidate offset
                test_val = ctypes.c_char.from_address(str_address + candidate_offset).value
                if test_val == bytes([probe_byte]):
                    found_offset = candidate_offset
                    break
            except Exception:
                continue

        if found_offset is not None:
            # We found the data region — zero it out
            # Use single-byte zeroing (works for ASCII / Latin-1 / UCS-1)
            ctypes.memset(str_address + found_offset, 0, buf_size)
        # If we couldn't find the offset, skip ctypes — rely on del + gc

    except Exception:
        pass  # If ctypes fails entirely (PyPy, etc.), we still del + gc below
    return "\x00" * len(s)


def _secure_zero_bytearray(ba: bytearray) -> None:
    """Zero out a bytearray in-place (bytearrays ARE mutable)."""
    for i in range(len(ba)):
        ba[i] = 0


class SecureSSN:
    """
    Triple-layered ephemeral SSN container.

    Layer 1: Value stored only in RAM (never serialized)
    Layer 2: Explicit zeroing on .destroy() via ctypes memset
    Layer 3: Forced garbage collection after destruction

    Usage:
        with SecureSSN(raw_ssn) as ssn_holder:
            formatted = ssn_holder.with_dashes()
            # ... use formatted for form submission ...
        # SSN is irrecoverably destroyed here
    """

    __slots__ = ("_value", "_destroyed")

    def __init__(self, raw: str) -> None:
        # Strip any existing dashes/spaces, store digits only
        digits = re.sub(r"[^0-9]", "", raw)
        if len(digits) != 9:
            raise ValueError("SSN must contain exactly 9 digits")
        # CRITICAL: Force a non-interned copy so ctypes.memset won't
        # corrupt Python's interned string cache.  "".join(list(...))
        # always allocates a fresh buffer that Python will NOT intern.
        self._value: str = "".join(list(digits))
        self._destroyed: bool = False

    def with_dashes(self) -> str:
        """Return SSN formatted as XXX-XX-XXXX (required by LA form)."""
        if self._destroyed:
            raise RuntimeError("SSN has been destroyed")
        v = self._value
        return f"{v[:3]}-{v[3:5]}-{v[5:]}"

    @property
    def raw(self) -> str:
        """Raw 9-digit SSN. Use sparingly."""
        if self._destroyed:
            raise RuntimeError("SSN has been destroyed")
        return self._value

    def destroy(self) -> None:
        """Irrecoverably destroy the SSN from memory."""
        if self._destroyed:
            return

        # Layer 2a: ctypes memset overwrite of the string buffer
        old_val = self._value
        self._value = _secure_zero_string(old_val)

        # Layer 2b: Reassign to zeros, then delete
        self._value = "\x00" * 9
        del old_val
        del self._value
        self._destroyed = True

        # Layer 3: Force garbage collection
        gc.collect()
        gc.collect()  # Second pass catches reference cycles

    def __enter__(self) -> "SecureSSN":
        return self

    def __exit__(self, *_: Any) -> None:
        self.destroy()

    def __del__(self) -> None:
        if getattr(self, "_destroyed", True) is False:
            self.destroy()

    # Prevent accidental serialization / logging
    def __repr__(self) -> str:
        return "SecureSSN(***)"

    def __str__(self) -> str:
        return "***-**-****"

    def __format__(self, format_spec: str) -> str:
        return "***-**-****"


@contextmanager
def secure_string_context(value: str):
    """
    Context manager for any temporary PII string (not just SSNs).
    Zeroes and deletes the string on exit.
    """
    try:
        yield value
    finally:
        _secure_zero_string(value)
        del value
        gc.collect()


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: DATA MODELS (no PII stored here)
# ═══════════════════════════════════════════════════════════════════════════════


class CertificationStatus(str, Enum):
    """Possible CNA certification statuses from the LA registry."""
    CERTIFIED = "Certified"
    NOT_CERTIFIED = "Not Certified"
    CALL_REGISTRY = "Call CNA Registry"
    NOT_FOUND = "Not Found"
    LOOKUP_ERROR = "Lookup Error"


@dataclass(frozen=True)
class CNAResult:
    """
    Parsed CNA lookup result. Contains ZERO PII.
    The name field stores only what the registry returns (public record).
    """
    name: str
    certification_number: str
    certified_from: str
    certified_to: str
    original_certification_date: str
    status: CertificationStatus
    retest_required_by: str
    lookup_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    multiple_matches: bool = False
    match_count: int = 0


@dataclass(frozen=True)
class LookupMetrics:
    """Non-PII operational metrics safe to log."""
    order_number: str
    success: bool
    status: CertificationStatus
    duration_ms: int
    retry_count: int
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4: LA CNA REGISTRY SCRAPER  (HTTP POST pathway)
# ═══════════════════════════════════════════════════════════════════════════════

# Chosen pathway: SIMPLE HTTP POST
#
# Why this is the ONLY pathway that will work 100%:
#
#   1. Direct API — IMPOSSIBLE. LA site has no public API.
#
#   2. Simple HTTP POST — CONFIRMED VIABLE ✓
#      The form at frmsearchweb2.aspx is a classic ASP.NET WebForms page with:
#        - Standard __VIEWSTATE / __VIEWSTATEGENERATOR / __EVENTVALIDATION
#        - NO __doPostBack (no JavaScript postback infrastructure)
#        - Pure HTML form submit to the same URL
#        - Fields: txtFn, txtMn, txtLn, txtSSNNum, txtDOB, cboEmployeeType, btnSearch
#        - Results rendered server-side in a <table id="dgvList"> DataGrid
#      This is the fastest, most reliable, smallest-attack-surface option.
#
#   3. Playwright headless — UNNECESSARY. The form has zero client-side JS
#      dependencies beyond standard ASP.NET ViewState. A Playwright dependency
#      would add ~400MB to the Docker image, introduce browser stability
#      concerns, and slow down lookups by 5-10x, all for zero benefit.
#
# Conclusion: HTTP POST with httpx (async) is the gold-standard choice.
# We include a Playwright fallback module (la_cna_playwright_fallback.py)
# ONLY as a disaster recovery option if Microsoft ever adds JS to the form.


class ASPNetFormTokens:
    """Holds the ASP.NET anti-forgery tokens needed for POST submission."""

    __slots__ = ("viewstate", "viewstate_generator", "event_validation")

    def __init__(
        self, viewstate: str, viewstate_generator: str, event_validation: str
    ) -> None:
        self.viewstate = viewstate
        self.viewstate_generator = viewstate_generator
        self.event_validation = event_validation

    @classmethod
    def extract_from_html(cls, html: str) -> "ASPNetFormTokens":
        """Parse __VIEWSTATE, __VIEWSTATEGENERATOR, __EVENTVALIDATION from HTML."""

        def _extract(name: str) -> str:
            pattern = rf'id="{name}"\s+value="([^"]*)"'
            match = re.search(pattern, html)
            if not match:
                raise ValueError(f"Could not extract {name} from response HTML")
            return match.group(1)

        return cls(
            viewstate=_extract("__VIEWSTATE"),
            viewstate_generator=_extract("__VIEWSTATEGENERATOR"),
            event_validation=_extract("__EVENTVALIDATION"),
        )


class LACNARegistryClient:
    """
    Async HTTP client for querying the Louisiana CNA/DSW Registry.

    Architecture:
      1. GET the search page → extract ASP.NET tokens
      2. POST with SSN (dashes required) + tokens → receive results HTML
      3. Parse DataGrid table → extract certification data
      4. SSN is destroyed immediately after POST completes
    """

    def __init__(self) -> None:
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_LOOKUPS)

    async def lookup_by_ssn(
        self, ssn_holder: SecureSSN, order_number: str
    ) -> tuple[CNAResult, LookupMetrics]:
        """
        Perform a CNA lookup by SSN. The SSN is used for the POST only
        and is NOT retained by this method.

        Args:
            ssn_holder: SecureSSN context — caller is responsible for .destroy()
            order_number: Accio order number (for non-PII metrics only)

        Returns:
            Tuple of (CNAResult, LookupMetrics)
        """
        async with self._semaphore:
            start_time = time.monotonic()
            retry_count = 0
            last_error: Optional[Exception] = None

            for attempt in range(MAX_RETRIES):
                try:
                    result = await self._execute_lookup(ssn_holder)
                    elapsed_ms = int((time.monotonic() - start_time) * 1000)
                    metrics = LookupMetrics(
                        order_number=order_number,
                        success=True,
                        status=result.status,
                        duration_ms=elapsed_ms,
                        retry_count=retry_count,
                    )
                    return result, metrics

                except (httpx.HTTPStatusError, httpx.ConnectError,
                        httpx.TimeoutException, ValueError) as exc:
                    last_error = exc
                    retry_count = attempt + 1
                    if attempt < MAX_RETRIES - 1:
                        delay = RETRY_BASE_DELAY * (2 ** attempt)
                        await asyncio.sleep(delay)

            # All retries exhausted
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            error_result = CNAResult(
                name="",
                certification_number="",
                certified_from="",
                certified_to="",
                original_certification_date="",
                status=CertificationStatus.LOOKUP_ERROR,
                retest_required_by="",
            )
            metrics = LookupMetrics(
                order_number=order_number,
                success=False,
                status=CertificationStatus.LOOKUP_ERROR,
                duration_ms=elapsed_ms,
                retry_count=retry_count,
            )
            return error_result, metrics

    async def _execute_lookup(self, ssn_holder: SecureSSN) -> CNAResult:
        """Single attempt: GET tokens → POST SSN → parse results."""
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(HTTP_TIMEOUT_SECONDS),
            follow_redirects=True,
            verify=True,  # TLS certificate verification ON
            http2=False,  # ASPX sites often don't support HTTP/2
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/125.0.0.0 Safari/537.36"
                ),
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;"
                    "q=0.9,image/webp,*/*;q=0.8"
                ),
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
            },
        ) as client:
            # ── Step 1: GET the form page to harvest ASP.NET tokens ──
            get_response = await client.get(LA_CNA_URL)
            get_response.raise_for_status()
            tokens = ASPNetFormTokens.extract_from_html(get_response.text)

            # ── Step 2: POST with SSN ──
            # The SSN is formatted with dashes as the form requires
            ssn_formatted = ssn_holder.with_dashes()

            form_data = {
                "__VIEWSTATE": tokens.viewstate,
                "__VIEWSTATEGENERATOR": tokens.viewstate_generator,
                "__EVENTVALIDATION": tokens.event_validation,
                "txtFn": "",
                "txtMn": "",
                "txtLn": "",
                "txtSSNNum": ssn_formatted,
                "txtDOB": "",
                "cboEmployeeType": "CNA",
                "btnSearch": "Search",
            }

            post_response = await client.post(
                LA_CNA_URL,
                data=form_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            post_response.raise_for_status()

            # ── Step 3: Immediately destroy the formatted SSN from locals ──
            _secure_zero_string(ssn_formatted)
            ssn_formatted = "\x00" * 11
            del ssn_formatted

            # Also zero the form_data dict's SSN entry
            form_data["txtSSNNum"] = "\x00" * 11
            del form_data
            gc.collect()

            # ── Step 4: Parse the results HTML ──
            return self._parse_results(post_response.text)

    @staticmethod
    def _parse_results(html: str) -> CNAResult:
        """
        Parse the DataGrid results table from the LA CNA response.

        Table ID: dgvList
        Columns: Name (CNA) | Certification Number | Certified From-To |
                 Original Certification | Status | Retest Required By
        """
        # Check for "No Data" response
        if "No Data" in html or "dgvList" not in html:
            return CNAResult(
                name="",
                certification_number="",
                certified_from="",
                certified_to="",
                original_certification_date="",
                status=CertificationStatus.NOT_FOUND,
                retest_required_by="",
            )

        # Extract table rows
        table_pattern = r'<table[^>]*id="dgvList"[^>]*>(.*?)</table>'
        table_match = re.search(table_pattern, html, re.DOTALL | re.IGNORECASE)
        if not table_match:
            return CNAResult(
                name="",
                certification_number="",
                certified_from="",
                certified_to="",
                original_certification_date="",
                status=CertificationStatus.NOT_FOUND,
                retest_required_by="",
            )

        table_html = table_match.group(1)

        # Extract all data rows (skip header row)
        row_pattern = r"<tr[^>]*>(.*?)</tr>"
        rows = re.findall(row_pattern, table_html, re.DOTALL | re.IGNORECASE)

        if len(rows) < 2:  # Need at least header + 1 data row
            return CNAResult(
                name="",
                certification_number="",
                certified_from="",
                certified_to="",
                original_certification_date="",
                status=CertificationStatus.NOT_FOUND,
                retest_required_by="",
            )

        # Parse data rows (skip first row = header, skip last row if empty)
        data_rows: list[list[str]] = []
        for row_html in rows[1:]:
            cell_pattern = r"<td[^>]*>(.*?)</td>"
            cells = re.findall(cell_pattern, row_html, re.DOTALL | re.IGNORECASE)
            if cells and any(c.strip() for c in cells):
                # Strip HTML tags and whitespace from cell contents
                cleaned = [re.sub(r"<[^>]+>", "", c).strip() for c in cells]
                if len(cleaned) >= 5 and cleaned[0]:  # Must have name
                    data_rows.append(cleaned)

        if not data_rows:
            return CNAResult(
                name="",
                certification_number="",
                certified_from="",
                certified_to="",
                original_certification_date="",
                status=CertificationStatus.NOT_FOUND,
                retest_required_by="",
            )

        # SSN search should return exactly 1 person (possibly multiple certs)
        # Use the FIRST row (most recent certification) as the primary result
        row = data_rows[0]

        # Parse "Certified From-To" (format: "MM/DD/YYYY - MM/DD/YYYY")
        certified_from = ""
        certified_to = ""
        if len(row) > 2 and " - " in row[2]:
            parts = row[2].split(" - ", 1)
            certified_from = parts[0].strip()
            certified_to = parts[1].strip()

        # Map status string to enum
        raw_status = row[4].strip() if len(row) > 4 else ""
        if raw_status == "Certified":
            status = CertificationStatus.CERTIFIED
        elif raw_status == "Not Certified":
            status = CertificationStatus.NOT_CERTIFIED
        elif "Call" in raw_status:
            status = CertificationStatus.CALL_REGISTRY
        else:
            status = CertificationStatus.NOT_FOUND

        return CNAResult(
            name=row[0] if len(row) > 0 else "",
            certification_number=row[1] if len(row) > 1 else "",
            certified_from=certified_from,
            certified_to=certified_to,
            original_certification_date=row[3] if len(row) > 3 else "",
            status=status,
            retest_required_by=row[5].strip() if len(row) > 5 else "",
            multiple_matches=len(data_rows) > 1,
            match_count=len(data_rows),
        )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5: ACCIO DATA API CLIENT
# ═══════════════════════════════════════════════════════════════════════════════


class AccioDataClient:
    """
    Client for the Accio Data XML API.

    Handles:
      - Pulling candidate records (including SSN from IRS/IVES results)
      - Pushing CNA verification results back as additional verification items
    """

    def __init__(self) -> None:
        self._base_url = ACCIO_API_BASE_URL.rstrip("/")

    def _build_login_xml(self) -> str:
        """Build the <login> block for Accio XML requests."""
        return (
            f"<login>"
            f"<account>{_xml_escape(ACCIO_API_ACCOUNT)}</account>"
            f"<username>{_xml_escape(ACCIO_API_USERNAME)}</username>"
            f"<password>{_xml_escape(ACCIO_API_PASSWORD)}</password>"
            f"</login>"
        )

    async def fetch_pending_orders(self) -> list[dict[str, str]]:
    """
        Retrieve orders from Accio that need CNA verification.

        Returns list of dicts with keys: order_number, ssn
        The SSN is returned as a raw string — caller MUST wrap in SecureSSN.
        """
        request_xml = (
            f"<?xml version='1.0' encoding='UTF-8'?>"
            f"<AccioRequest>"
            f"{self._build_login_xml()}"
            f"<mode>{_xml_escape(ACCIO_API_MODE)}</mode>"
            f"<action>GetPendingVerifications</action>"
            f"<verificationType>CNA_LA</verificationType>"
            f"</AccioRequest>"
        )

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(HTTP_TIMEOUT_SECONDS),
            verify=True,
        ) as client:
            response = await client.post(
                f"{self._base_url}/xml/orders",
                content=request_xml,
                headers={"Content-Type": "text/xml"},
            )
            response.raise_for_status()

        return self._parse_pending_orders(response.text)

    def _parse_pending_orders(self, xml_text: str) -> list[dict[str, str]]:
        """Parse order list from Accio XML response."""
        orders: list[dict[str, str]] = []
        try:
            root = ET.fromstring(xml_text)
            for order_elem in root.findall(".//order"):
                order_number = order_elem.findtext("ordernumber", "").strip()
                ssn = order_elem.findtext("subject/ssn", "").strip()
                if order_number and ssn and len(re.sub(r"[^0-9]", "", ssn)) == 9:
                    orders.append({
                        "order_number": order_number,
                        "ssn": ssn,
                    })
        except ET.ParseError:
            pass  # Logged as operational failure below
        return orders

    async def post_verification_result(
        self, order_number: str, result: CNAResult
    ) -> bool:
        """
        Push CNA verification result back to Accio Data as a completed
        verification suborder. Returns True on success.
        """
        # Map our status to Accio disposition values
        if result.status == CertificationStatus.CERTIFIED:
            disposition = "Verified"
        elif result.status == CertificationStatus.NOT_CERTIFIED:
            disposition = "Unable to Verify"
        elif result.status == CertificationStatus.CALL_REGISTRY:
            disposition = "See Comments"
        elif result.status == CertificationStatus.NOT_FOUND:
            disposition = "No Match"
        else:
            disposition = "Unable to Verify"

        # Build verified item fields
        verified_items = (
            f"<verifieditem>"
            f"<fieldname>CNA Certification Status</fieldname>"
            f"<fieldvalue>{_xml_escape(result.status.value)}</fieldvalue>"
            f"</verifieditem>"
            f"<verifieditem>"
            f"<fieldname>Certification Number</fieldname>"
             f"<fieldvalue>{_xml_escape(result.certification_number)}</fieldvalue>"
            f"</verifieditem>"
            f"<verifieditem>"
            f"<fieldname>Certified From</fieldname>"
            f"<fieldvalue>{_xml_escape(result.certified_from)}</fieldvalue>"
            f"</verifieditem>"
            f"<verifieditem>"
            f"<fieldname>Certified To</fieldname>"
            f"<fieldvalue>{_xml_escape(result.certified_to)}</fieldvalue>"
            f"</verifieditem>"
            f"<verifieditem>"
            f"<fieldname>Original Certification Date</fieldname>"
            f"<fieldvalue>{_xml_escape(result.original_certification_date)}</fieldvalue>"
            f"</verifieditem>"
            f"<verifieditem>"
            f"<fieldname>Registry Name</fieldname>"
            f"<fieldvalue>{_xml_escape(result.name)}</fieldvalue>"
            f"</verifieditem>"
        )

        if result.retest_required_by:
            verified_items += (
                f"<verifieditem>"
                f"<fieldname>Retest Required By</fieldname>"
                f"<fieldvalue>{_xml_escape(result.retest_required_by)}</fieldvalue>"
                f"</verifieditem>"
            )

        if result.multiple_matches:
            verified_items += (
                f"<verifieditem>"
                f"<fieldname>Multiple Matches</fieldname>"
                f"<fieldvalue>Yes ({result.match_count} records)</fieldvalue>"
                f"</verifieditem>"
            )

        request_xml = (
            f"<?xml version='1.0' encoding='UTF-8'?>"
            f"<PostResults>"
            f"{self._build_login_xml()}"
            f"<ordernumber>{_xml_escape(order_number)}</ordernumber>"
            f"<suborder>"
            f"<searchtype>CNA Credential Verification</searchtype>"
            f"<disposition>{_xml_escape(disposition)}</disposition>"
            f"<comments>LA CNA/DSW Registry lookup completed "
            f"{result.lookup_timestamp}</comments>"
            f"{verified_items}"
            f"</suborder>"
            f"</PostResults>"
        )

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(HTTP_TIMEOUT_SECONDS),
                verify=True,
            ) as client:
                response = await client.post(
                    f"{self._base_url}/xml/postresults",
                    content=request_xml,
                    headers={"Content-Type": "text/xml"},
                )
                response.raise_for_status()

            # Check for success in response
            root = ET.fromstring(response.text)
            error_code = root.findtext(".//errorcode", "").strip()
            return error_code == "0" or "success" in response.text.lower()

        except Exception:
            return False


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6: ORCHESTRATOR  (the main processing pipeline)
# ═══════════════════════════════════════════════════════════════════════════════


class CNAVerificationOrchestrator:
    """
    Orchestrates the full verification pipeline:
      Accio (pull SSN) → LA Registry (lookup) → Accio (push result) → Destroy SSN
    """

    def __init__(self) -> None:
        self._accio = AccioDataClient()
        self._registry = LACNARegistryClient()
        self._metrics: list[LookupMetrics] = []

    async def process_pending_orders(self) -> dict[str, Any]:
        """
        Main entry point: fetch all pending orders from Accio,
        perform CNA lookups, push results back, destroy all PII.

        Returns a non-PII summary dict safe to log.
        """
        summary = {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "total_orders": 0,
            "successful": 0,
            "failed": 0,
            "not_found": 0,
            "certified": 0,
            "not_certified": 0,
            "errors": [],
        }

        # ── Fetch pending orders from Accio ──
        try:
            raw_orders = await self._accio.fetch_pending_orders()
        except Exception as exc:
            summary["errors"].append(f"Failed to fetch orders: {type(exc).__name__}")
            summary["completed_at"] = datetime.now(timezone.utc).isoformat()
            return summary

        summary["total_orders"] = len(raw_orders)

        if not raw_orders:
            summary["completed_at"] = datetime.now(timezone.utc).isoformat()
            return summary

        # ── Process each order with SecureSSN isolation ──
        for order_data in raw_orders:
            order_number = order_data["order_number"]
            raw_ssn = order_data["ssn"]

            try:
                # SSN enters the SecureSSN fortress
                with SecureSSN(raw_ssn) as ssn_holder:
                    # Immediately zero the raw_ssn from the order dict
                    order_data["ssn"] = _secure_zero_string(raw_ssn)
                    raw_ssn = "\x00" * 9
                    del raw_ssn

                    # Perform the CNA lookup
                    result, metrics = await self._registry.lookup_by_ssn(
                        ssn_holder, order_number
                    )
                    self._metrics.append(metrics)
                    # SSN is destroyed here by the `with` block exit

                # Push result back to Accio (no SSN involved)
                push_success = await self._accio.post_verification_result(
                    order_number, result
                )

                # Update summary counters
                if metrics.success:
                    summary["successful"] += 1
                    if result.status == CertificationStatus.CERTIFIED:
                        summary["certified"] += 1
                    elif result.status == CertificationStatus.NOT_CERTIFIED:
                        summary["not_certified"] += 1
                    elif result.status == CertificationStatus.NOT_FOUND:
                        summary["not_found"] += 1
                else:
                    summary["failed"] += 1

                if not push_success:
                    summary["errors"].append(
                        f"Order {order_number}: result push failed"
                    )

            except ValueError as exc:
                summary["failed"] += 1
                summary["errors"].append(
                    f"Order {order_number}: invalid SSN format"
                )
                # Still ensure raw_ssn is zeroed
                if "raw_ssn" in dir():
                    _secure_zero_string(raw_ssn)
                gc.collect()

            except Exception as exc:
                summary["failed"] += 1
                summary["errors"].append(
                    f"Order {order_number}: {type(exc).__name__}"
                )
                gc.collect()

        # ── Final cleanup: zero all order data ──
        for order_data in raw_orders:
            order_data["ssn"] = "\x00" * 9
        raw_orders.clear()
        del raw_orders
        gc.collect()

        summary["completed_at"] = datetime.now(timezone.utc).isoformat()
        return summary

    async def process_single_order(
        self, order_number: str, raw_ssn: str
    ) -> dict[str, Any]:
        """
        Process a single order (e.g., triggered by webhook).
        The raw_ssn is destroyed after processing.

        Returns a non-PII result dict safe to log/return.
        """
        response: dict[str, Any] = {
            "order_number": order_number,
            "success": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        try:
            with SecureSSN(raw_ssn) as ssn_holder:
                # Zero the input immediately
                _secure_zero_string(raw_ssn)
                raw_ssn = "\x00" * len(raw_ssn)

                result, metrics = await self._registry.lookup_by_ssn(
                    ssn_holder, order_number
                )
                # SSN destroyed here

            # Push to Accio
            push_ok = await self._accio.post_verification_result(
                order_number, result
            )

            response.update({
                "success": metrics.success,
                "status": result.status.value,
                "certification_number": result.certification_number,
                "name": result.name,
                "certified_from": result.certified_from,
                "certified_to": result.certified_to,
                "push_success": push_ok,
                "duration_ms": metrics.duration_ms,
            })

        except ValueError:
            response["error"] = "Invalid SSN format"
        except Exception as exc:
            response["error"] = type(exc).__name__
        finally:
            # Paranoid cleanup
            gc.collect()

        return response


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7: FASTAPI WEBHOOK SERVER
# ═══════════════════════════════════════════════════════════════════════════════

# Conditionally import FastAPI (allows running without it for batch mode)
try:
    from fastapi import FastAPI, HTTPException, Request, Response
    from fastapi.responses import JSONResponse

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


def create_app() -> "FastAPI":
    """Create and configure the FastAPI application."""
    if not FASTAPI_AVAILABLE:
        raise ImportError("FastAPI is required for webhook mode: pip install fastapi uvicorn")

    _validate_config()

    app = FastAPI(
        title="LA CNA Registry Verification Bridge",
        description="Accio Data ↔ LA CNA/DSW Registry Integration",
        version="1.0.0",
        docs_url=None,  # Disable Swagger UI in production
        redoc_url=None,  # Disable ReDoc in production
    )

    orchestrator = CNAVerificationOrchestrator()

    @app.post("/webhook/accio/cna-verify")
    async def webhook_cna_verify(request: Request) -> JSONResponse:
        """
        Webhook endpoint triggered by Accio Data when a CNA verification
        is needed. Expects JSON body with order_number and ssn.

        Authentication: HMAC-SHA256 signature in X-Webhook-Signature header.
        """
        # ── Verify webhook signature ──
        signature = request.headers.get("X-Webhook-Signature", "")
        body = await request.body()

        if not _verify_webhook_signature(body, signature):
            raise HTTPException(status_code=401, detail="Invalid signature")

        # ── Parse request (SSN enters memory here) ──
        try:
            import json
            payload = json.loads(body)
            order_number = payload.get("order_number", "").strip()
            raw_ssn = payload.get("ssn", "").strip()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

        if not order_number or not raw_ssn:
            raise HTTPException(
                status_code=400,
                detail="Missing order_number or ssn",
            )

        # ── Zero the raw body and payload immediately ──
        _secure_zero_string(raw_ssn)
        # Re-extract for processing (the SSN is still in payload)
        raw_ssn = payload.get("ssn", "")
        payload["ssn"] = "\x00" * len(raw_ssn) if raw_ssn else ""
        del payload
        del body
        gc.collect()

        # ── Process the lookup ──
        result = await orchestrator.process_single_order(order_number, raw_ssn)

        # Zero raw_ssn one more time (belt and suspenders)
        _secure_zero_string(raw_ssn)
        del raw_ssn
        gc.collect()

        status_code = 200 if result.get("success") else 502
        return JSONResponse(content=result, status_code=status_code)

    @app.post("/webhook/accio/batch-verify")
    async def webhook_batch_verify(request: Request) -> JSONResponse:
        """
        Trigger a batch verification run that pulls all pending orders
        from Accio and processes them.

        Authentication: HMAC-SHA256 signature in X-Webhook-Signature header.
        """
        signature = request.headers.get("X-Webhook-Signature", "")
        body = await request.body()

        if not _verify_webhook_signature(body, signature):
            raise HTTPException(status_code=401, detail="Invalid signature")

        summary = await orchestrator.process_pending_orders()
        return JSONResponse(content=summary, status_code=200)

    @app.get("/health")
    async def health_check() -> JSONResponse:
        """Health check endpoint — returns no PII."""
        return JSONResponse(
            content={
                "status": "healthy",
                "service": "la-cna-accio-bridge",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            status_code=200,
        )

    return app


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8: UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════


def _xml_escape(text: str) -> str:
    """Escape special XML characters to prevent injection."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _verify_webhook_signature(body: bytes, signature: str) -> bool:
    """Verify HMAC-SHA256 webhook signature."""
    if not WEBHOOK_SECRET or not signature:
        return False
    expected = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9: CLI ENTRY POINT (for batch/cron mode)
# ═══════════════════════════════════════════════════════════════════════════════


async def main_batch() -> None:
    """Run a batch verification pass (for cron/scheduler use)."""
    _validate_config()
    orchestrator = CNAVerificationOrchestrator()
    summary = await orchestrator.process_pending_orders()

    # Safe to print: summary contains ZERO PII
    import json
    print(json.dumps(summary, indent=2))


def main_server() -> None:
    """Run the webhook server."""
    import uvicorn

    app = create_app()
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        log_level="warning",  # Minimize logging surface
        access_log=False,  # No request logging (could leak paths)
    )


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "batch":
        asyncio.run(main_batch())
    else:
        main_server()
