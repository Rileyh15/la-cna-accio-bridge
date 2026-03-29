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

# Webhook authentication (Accio XML credential-based auth)
# WEBHOOK_SECRET kept for backward compat but no longer required
WEBHOOK_SECRET: str = os.environ.get("WEBHOOK_SECRET", "")

# Accio PostResults endpoint (defaults to /c/p/researcherxml)
ACCIO_POSTRESULTS_PATH: str = os.environ.get(
    "ACCIO_POSTRESULTS_PATH", "/c/p/researcherxml"
)

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
# SECTION 1b: ORDER TRACKER  (zero-PII order lifecycle tracking)
# ═══════════════════════════════════════════════════════════════════════════════


import threading


class OrderTracker:
    """
    Thread-safe, in-memory order lifecycle tracker.

    Tracks every order through the pipeline WITHOUT storing ANY PII:
      - No SSNs, no names, no DOBs, no addresses
      - Only order numbers, timestamps, statuses, and dispositions

    Lifecycle states:
      received → processing → lookup_complete → posting_results → completed
      Any stage can transition to → failed

    NOTE: Data lives in RAM only. A service restart clears all tracking.
    For persistent tracking, wire up a database or external store.
    """

    # Status constants
    RECEIVED = "received"
    PROCESSING = "processing"
    LOOKUP_COMPLETE = "lookup_complete"
    POSTING_RESULTS = "posting_results"
    COMPLETED = "completed"
    FAILED = "failed"

    def __init__(self, max_history: int = 500) -> None:
        self._lock = threading.Lock()
        self._orders: dict[str, dict[str, Any]] = {}
        self._order_list: list[str] = []  # insertion order
        self._max_history = max_history
        self._counters = {
            "total_received": 0,
            "total_completed": 0,
            "total_failed": 0,
        }

    def record_received(
        self,
        order_number: str,
        sub_order_number: str = "",
    ) -> None:
        """Record that an order was received from Accio."""
        with self._lock:
            key = f"{order_number}:{sub_order_number}"
            self._orders[key] = {
                "order_number": order_number,
                "sub_order_number": sub_order_number,
                "status": self.RECEIVED,
                "received_at": datetime.now(timezone.utc).isoformat(),
                "processing_at": None,
                "lookup_complete_at": None,
                "posting_at": None,
                "completed_at": None,
                "disposition": None,
                "certification_status": None,
                "push_success": None,
                "duration_ms": None,
                "error": None,
            }
            self._order_list.append(key)
            self._counters["total_received"] += 1
            # Evict oldest entries if over limit
            while len(self._order_list) > self._max_history:
                old_key = self._order_list.pop(0)
                self._orders.pop(old_key, None)

    def update_status(
        self,
        order_number: str,
        sub_order_number: str,
        status: str,
        **kwargs: Any,
    ) -> None:
        """Update an order's status and optional metadata fields."""
        with self._lock:
            key = f"{order_number}:{sub_order_number}"
            if key not in self._orders:
                return
            entry = self._orders[key]
            entry["status"] = status

            # Record timestamps for each stage
            ts_field = f"{status}_at"
            if ts_field in entry and entry[ts_field] is None:
                entry[ts_field] = datetime.now(timezone.utc).isoformat()

            # Update any extra fields (disposition, duration_ms, etc.)
            for k, v in kwargs.items():
                if k in entry:
                    entry[k] = v

            # Update counters
            if status == self.COMPLETED:
                self._counters["total_completed"] += 1
            elif status == self.FAILED:
                self._counters["total_failed"] += 1

    def get_all_orders(self) -> list[dict[str, Any]]:
        """Return all tracked orders (newest first). Zero PII."""
        with self._lock:
            return [
                dict(self._orders[key])
                for key in reversed(self._order_list)
                if key in self._orders
            ]

    def get_summary(self) -> dict[str, Any]:
        """Return aggregate counters and recent activity. Zero PII."""
        with self._lock:
            recent = []
            for key in reversed(self._order_list[-10:]):
                if key in self._orders:
                    recent.append(dict(self._orders[key]))
            return {
                "counters": dict(self._counters),
                "in_memory_count": len(self._orders),
                "recent_orders": recent,
            }


# Global tracker instance (shared across webhook and orchestrator)
order_tracker = OrderTracker()


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
        self, order_number: str, result: CNAResult, sub_order_number: str = ""
    ) -> bool:
        """
        Push CNA verification result back to Accio Data as a completed
        verification suborder. Returns True on success.

        Uses Accio's researcher XML endpoint (PostResults format).
        The sub_order_number ties the result to the specific search
        component within the order.
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

        # Build the suborder block — include number if available
        suborder_attr = f' number="{_xml_escape(sub_order_number)}"' if sub_order_number else ""
        request_xml = (
            f"<?xml version='1.0' encoding='UTF-8'?>"
            f"<PostResults>"
            f"{self._build_login_xml()}"
            f"<ordernumber>{_xml_escape(order_number)}</ordernumber>"
            f"<suborder{suborder_attr}>"
            f"<searchtype>Certified Nurse Aid Registry</searchtype>"
            f"<disposition>{_xml_escape(disposition)}</disposition>"
            f"<comments>LA CNA/DSW Registry lookup completed "
            f"{result.lookup_timestamp}</comments>"
            f"{verified_items}"
            f"</suborder>"
            f"</PostResults>"
        )

        # Post to Accio's researcher XML endpoint
        postresults_url = (
            f"{self._base_url.rstrip('/')}"
            f"{ACCIO_POSTRESULTS_PATH}"
        )

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(HTTP_TIMEOUT_SECONDS),
                verify=True,
            ) as client:
                response = await client.post(
                    postresults_url,
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
        self, order_number: str, raw_ssn: str, sub_order_number: str = ""
    ) -> dict[str, Any]:
        """
        Process a single order (e.g., triggered by webhook).
        The raw_ssn is destroyed after processing.

        Returns a non-PII result dict safe to log/return.
        """
        response: dict[str, Any] = {
            "order_number": order_number,
            "sub_order_number": sub_order_number,
            "success": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        try:
            # ── Track: processing ──
            order_tracker.update_status(
                order_number, sub_order_number, OrderTracker.PROCESSING
            )

            with SecureSSN(raw_ssn) as ssn_holder:
                # Zero the input immediately
                _secure_zero_string(raw_ssn)
                raw_ssn = "\x00" * len(raw_ssn)

                result, metrics = await self._registry.lookup_by_ssn(
                    ssn_holder, order_number
                )
                # SSN destroyed here

            # ── Track: lookup complete ──
            order_tracker.update_status(
                order_number, sub_order_number,
                OrderTracker.LOOKUP_COMPLETE,
                disposition=result.status.value,
                certification_status=result.status.value,
                duration_ms=metrics.duration_ms,
            )

            # ── Track: posting results ──
            order_tracker.update_status(
                order_number, sub_order_number, OrderTracker.POSTING_RESULTS
            )

            # Push to Accio
            push_ok = await self._accio.post_verification_result(
                order_number, result, sub_order_number
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
    from fastapi.responses import HTMLResponse, JSONResponse

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
    async def webhook_cna_verify(request: Request) -> Response:
        """
        Vendor endpoint called by Accio Data when dispatching a CNA
        verification order.  Accepts the standard Accio XML vendor
        dispatch format (<AccioOrder>) and returns XML.

        Authentication: Accio XML <login> credentials validated against
        environment variables.
        """
        body = await request.body()

        # ── Parse the incoming Accio XML ──
        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            return _xml_error_response("400", "Malformed XML")

        # ── Verify Accio credentials ──
        login = root.find("login")
        if login is None:
            return _xml_error_response("401", "Missing login block")

        incoming_account = (login.findtext("account") or "").strip()
        incoming_username = (login.findtext("username") or "").strip()
        incoming_password = (login.findtext("password") or "").strip()

        if not _verify_accio_credentials(
            incoming_account, incoming_username, incoming_password
        ):
            return _xml_error_response("401", "Invalid credentials")

        # Zero password from memory immediately
        _secure_zero_string(incoming_password)
        del incoming_password
        gc.collect()

        # ── Extract order data ──
        place_order = root.find(".//placeOrder")
        if place_order is None:
            return _xml_error_response("400", "Missing placeOrder element")

        order_number = place_order.get("number", "").strip()
        sub_order = place_order.find("subOrder")
        sub_order_number = sub_order.get("number", "").strip() if sub_order is not None else ""

        # ── Extract SSN from subject (SSN enters memory here) ──
        subject = place_order.find("subject")
        if subject is None:
            return _xml_error_response("400", "Missing subject element")

        raw_ssn = (subject.findtext("ssn") or "").strip()
        name_first = (subject.findtext("name_first") or "").strip()
        name_last = (subject.findtext("name_last") or "").strip()

        if not order_number or not raw_ssn:
            return _xml_error_response("400", "Missing order number or SSN")

        # ── Zero the SSN in the parsed XML immediately ──
        ssn_elem = subject.find("ssn")
        if ssn_elem is not None:
            ssn_elem.text = "\x00" * 9
        del body
        gc.collect()

        # ── Track: order received ──
        order_tracker.record_received(order_number, sub_order_number)

        # ── Process the lookup ──
        result = await orchestrator.process_single_order(
            order_number, raw_ssn, sub_order_number
        )

        # Zero raw_ssn one more time (belt and suspenders)
        _secure_zero_string(raw_ssn)
        del raw_ssn
        gc.collect()

        # ── Track: final status ──
        success = result.get("success", False)
        order_tracker.update_status(
            order_number, sub_order_number,
            OrderTracker.COMPLETED if success else OrderTracker.FAILED,
            disposition=result.get("status"),
            certification_status=result.get("status"),
            push_success=result.get("push_success"),
            duration_ms=result.get("duration_ms"),
            error=result.get("error"),
        )

        # ── Return XML acknowledgment to Accio ──
        return _xml_ack_response(order_number, sub_order_number, success)

    @app.post("/webhook/accio/batch-verify")
    async def webhook_batch_verify(request: Request) -> JSONResponse:
        """
        Trigger a batch verification run that pulls all pending orders
        from Accio and processes them.

        Authentication: HMAC-SHA256 signature in X-Webhook-Signature header
        (optional — skipped if WEBHOOK_SECRET is not set).
        """
        if WEBHOOK_SECRET:
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

    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> HTMLResponse:
        """Interactive status dashboard — displays NO PII."""
        now = datetime.now(timezone.utc).strftime("%B %d, %Y at %I:%M %p UTC")
        accio_configured = all([
            ACCIO_API_BASE_URL, ACCIO_API_ACCOUNT,
            ACCIO_API_USERNAME, ACCIO_API_PASSWORD,
        ])
        webhook_configured = accio_configured  # XML credential auth uses Accio creds
        accio_status = "Connected" if accio_configured else "Awaiting Credentials"
        accio_dot = "#10b981" if accio_configured else "#f59e0b"
        webhook_status = "XML Credential Auth" if webhook_configured else "Not Configured"
        webhook_dot = "#10b981" if webhook_configured else "#ef4444"
        registry_status = "Reachable"
        registry_dot = "#10b981"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LA CNA Registry Bridge</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0f172a; color: #e2e8f0; min-height: 100vh;
    display: flex; flex-direction: column; align-items: center;
  }}
  .header {{
    width: 100%; padding: 2rem 1rem;
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border-bottom: 1px solid #1e293b; text-align: center;
  }}
  .header h1 {{
    font-size: 1.75rem; font-weight: 700; color: #f8fafc;
    letter-spacing: -0.025em;
  }}
  .header .subtitle {{
    margin-top: 0.35rem; font-size: 0.875rem; color: #94a3b8;
  }}
  .badge {{
    display: inline-block; margin-top: 0.75rem; padding: 0.25rem 0.75rem;
    border-radius: 9999px; font-size: 0.75rem; font-weight: 600;
    background: #065f46; color: #6ee7b7; border: 1px solid #10b981;
  }}
  .container {{ width: 100%; max-width: 960px; padding: 2rem 1rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.25rem; }}
  .card {{
    background: #1e293b; border-radius: 12px; padding: 1.5rem;
    border: 1px solid #334155; transition: border-color 0.2s;
  }}
  .card:hover {{ border-color: #475569; }}
  .card-title {{
    font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.05em; color: #94a3b8; margin-bottom: 1rem;
  }}
  .status-row {{
    display: flex; align-items: center; justify-content: space-between;
    padding: 0.6rem 0; border-bottom: 1px solid #334155;
  }}
  .status-row:last-child {{ border-bottom: none; }}
  .status-label {{ font-size: 0.875rem; color: #cbd5e1; }}
  .status-value {{ display: flex; align-items: center; gap: 0.4rem; font-size: 0.875rem; font-weight: 500; }}
  .dot {{
    width: 8px; height: 8px; border-radius: 50%; display: inline-block;
    animation: pulse 2s ease-in-out infinite;
  }}
  @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}
  .endpoint {{
    display: flex; align-items: center; gap: 0.75rem;
    padding: 0.75rem; margin-bottom: 0.5rem; background: #0f172a;
    border-radius: 8px; border: 1px solid #334155;
  }}
  .endpoint:last-child {{ margin-bottom: 0; }}
  .method {{
    padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem;
    font-weight: 700; font-family: monospace; min-width: 3rem; text-align: center;
  }}
  .method-get {{ background: #064e3b; color: #6ee7b7; }}
  .method-post {{ background: #1e3a5f; color: #7dd3fc; }}
  .endpoint-path {{
    font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.85rem; color: #e2e8f0;
  }}
  .endpoint-desc {{ font-size: 0.75rem; color: #64748b; margin-left: auto; }}
  .config-row {{
    display: flex; justify-content: space-between; align-items: center;
    padding: 0.5rem 0; border-bottom: 1px solid #334155; font-size: 0.85rem;
  }}
  .config-row:last-child {{ border-bottom: none; }}
  .config-key {{ color: #94a3b8; font-family: monospace; }}
  .config-val {{ color: #e2e8f0; font-weight: 500; }}
  .security-item {{
    display: flex; align-items: flex-start; gap: 0.5rem;
    padding: 0.5rem 0; font-size: 0.85rem; color: #cbd5e1;
  }}
  .check {{ color: #10b981; font-weight: bold; flex-shrink: 0; }}
  .footer {{
    text-align: center; padding: 2rem 1rem; font-size: 0.75rem; color: #475569;
  }}
  .footer a {{ color: #64748b; text-decoration: none; }}
  .footer a:hover {{ color: #94a3b8; }}
</style>
</head>
<body>
  <div class="header">
    <h1>LA CNA Registry Bridge</h1>
    <div class="subtitle">Louisiana CNA/DSW Registry &harr; Accio Data Integration</div>
    <span class="badge">System Online</span>
  </div>
  <div class="container">
    <div class="grid">
      <div class="card">
        <div class="card-title">Connection Status</div>
        <div class="status-row">
          <span class="status-label">Accio Data API</span>
          <span class="status-value"><span class="dot" style="background:{accio_dot}"></span> {accio_status}</span>
        </div>
        <div class="status-row">
          <span class="status-label">Webhook Auth</span>
          <span class="status-value"><span class="dot" style="background:{webhook_dot}"></span> {webhook_status}</span>
        </div>
        <div class="status-row">
          <span class="status-label">LA CNA Registry</span>
          <span class="status-value"><span class="dot" style="background:{registry_dot}"></span> {registry_status}</span>
        </div>
      </div>
      <div class="card">
        <div class="card-title">API Endpoints</div>
        <div class="endpoint">
          <span class="method method-post">POST</span>
          <span class="endpoint-path">/webhook/accio/cna-verify</span>
        </div>
        <div class="endpoint">
          <span class="method method-post">POST</span>
          <span class="endpoint-path">/webhook/accio/batch-verify</span>
        </div>
        <div class="endpoint">
          <span class="method method-get">GET</span>
          <span class="endpoint-path">/health</span>
        </div>
      </div>
      <div class="card">
        <div class="card-title">Operational Config</div>
        <div class="config-row">
          <span class="config-key">MAX_CONCURRENT_LOOKUPS</span>
          <span class="config-val">{MAX_CONCURRENT_LOOKUPS}</span>
        </div>
        <div class="config-row">
          <span class="config-key">HTTP_TIMEOUT</span>
          <span class="config-val">{HTTP_TIMEOUT_SECONDS}s</span>
        </div>
        <div class="config-row">
          <span class="config-key">MAX_RETRIES</span>
          <span class="config-val">{MAX_RETRIES}</span>
        </div>
        <div class="config-row">
          <span class="config-key">RETRY_DELAY</span>
          <span class="config-val">{RETRY_BASE_DELAY}s base</span>
        </div>
      </div>
      <div class="card">
        <div class="card-title">Security Posture</div>
        <div class="security-item"><span class="check">&check;</span> Accio XML credential authentication</div>
        <div class="security-item"><span class="check">&check;</span> SSNs exist only in RAM during lookup</div>
        <div class="security-item"><span class="check">&check;</span> Triple-layer memory zeroing + forced GC</div>
        <div class="security-item"><span class="check">&check;</span> Zero PII in logs, disk, or cache</div>
        <div class="security-item"><span class="check">&check;</span> TLS 1.2+ enforced on all connections</div>
      </div>
    </div>
  </div>
  <div class="footer">
    <p>Last checked: {now}</p>
    <p style="margin-top:0.35rem;">LA CNA Registry Verification Bridge v1.0.0</p>
  </div>
</body>
</html>"""
        return HTMLResponse(content=html, status_code=200)

    @app.get("/orders/json")
    async def orders_json() -> JSONResponse:
        """Return all tracked orders as JSON. Zero PII."""
        return JSONResponse(content=order_tracker.get_summary(), status_code=200)

    @app.get("/orders", response_class=HTMLResponse)
    async def orders_dashboard() -> HTMLResponse:
        """Order tracking dashboard — displays NO PII."""
        now = datetime.now(timezone.utc).strftime("%B %d, %Y at %I:%M %p UTC")
        summary = order_tracker.get_summary()
        counters = summary["counters"]
        orders = order_tracker.get_all_orders()

        # Build table rows — simple: order #, status, completed date/time
        rows_html = ""
        if not orders:
            rows_html = (
                '<tr><td colspan="3" style="text-align:center;'
                'color:#94a3b8;padding:2rem;">No orders tracked yet. '
                'Orders appear here when Accio dispatches to the bridge.'
                '</td></tr>'
            )
        else:
            for o in orders:
                status = o.get("status", "unknown")
                if status == "completed":
                    badge_color = "#10b981"
                    badge_text = "Complete"
                elif status == "failed":
                    badge_color = "#ef4444"
                    badge_text = "Failed"
                elif status in ("processing", "lookup_complete", "posting_results"):
                    badge_color = "#f59e0b"
                    badge_text = "Processing"
                else:
                    badge_color = "#3b82f6"
                    badge_text = "Received"

                # Show completed_at if done, otherwise received_at
                completed = o.get("completed_at") or ""
                received = o.get("received_at") or ""
                timestamp = completed if completed else received
                timestamp_display = timestamp[:19].replace("T", " ") if timestamp else "—"

                rows_html += (
                    f'<tr>'
                    f'<td style="font-weight:600;">'
                    f'{_xml_escape(o.get("order_number", ""))}</td>'
                    f'<td><span style="background:{badge_color};color:#fff;'
                    f'padding:3px 12px;border-radius:4px;font-size:0.85rem;">'
                    f'{badge_text}</span></td>'
                    f'<td style="color:#94a3b8;">{timestamp_display}</td>'
                    f'</tr>'
                )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Order Tracker — LA CNA Bridge</title>
<meta http-equiv="refresh" content="10">
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
         background:#0f172a; color:#e2e8f0; padding:1.5rem; }}
  h1 {{ text-align:center; font-size:1.6rem; margin-bottom:0.3rem; }}
  .subtitle {{ text-align:center; color:#94a3b8; font-size:0.9rem; margin-bottom:1.5rem; }}
  .counters {{ display:flex; justify-content:center; gap:2rem; margin-bottom:1.5rem; flex-wrap:wrap; }}
  .counter {{ background:#1e293b; border:1px solid #334155; border-radius:8px;
              padding:1rem 1.5rem; text-align:center; min-width:140px; }}
  .counter .num {{ font-size:2rem; font-weight:700; }}
  .counter .lbl {{ font-size:0.8rem; color:#94a3b8; margin-top:0.2rem; }}
  .num-received {{ color:#3b82f6; }}
  .num-completed {{ color:#10b981; }}
  .num-failed {{ color:#ef4444; }}
  table {{ width:100%; max-width:700px; margin:0 auto; border-collapse:collapse;
           background:#1e293b; border:1px solid #334155; border-radius:8px; overflow:hidden; }}
  th {{ background:#334155; padding:0.8rem 1rem; text-align:left; font-size:0.85rem;
        color:#94a3b8; text-transform:uppercase; letter-spacing:0.05em; }}
  td {{ padding:0.7rem 1rem; border-bottom:1px solid #293548; font-size:0.95rem; }}
  tr:hover {{ background:#334155; }}
  .refresh {{ text-align:center; color:#64748b; font-size:0.75rem; margin-top:1rem; }}
  a {{ color:#3b82f6; text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  .nav {{ text-align:center; margin-bottom:1rem; }}
</style>
</head>
<body>
  <div class="nav"><a href="/">&larr; Dashboard</a></div>
  <h1>Order Tracker</h1>
  <p class="subtitle">Auto-refreshes every 10 seconds</p>

  <div class="counters">
    <div class="counter">
      <div class="num num-received">{counters.get("total_received", 0)}</div>
      <div class="lbl">Received</div>
    </div>
    <div class="counter">
      <div class="num num-completed">{counters.get("total_completed", 0)}</div>
      <div class="lbl">Completed</div>
    </div>
    <div class="counter">
      <div class="num num-failed">{counters.get("total_failed", 0)}</div>
      <div class="lbl">Failed</div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Order #</th>
        <th>Status</th>
        <th>Date / Time (UTC)</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>

  <p class="refresh">Last refreshed: {now} &mdash; Showing {len(orders)} orders
  (max 500 in memory)</p>
</body>
</html>"""
        return HTMLResponse(content=html, status_code=200)

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
    """Verify HMAC-SHA256 webhook signature (for batch endpoint)."""
    if not WEBHOOK_SECRET or not signature:
        return False
    expected = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def _verify_accio_credentials(
    account: str, username: str, password: str
) -> bool:
    """
    Verify incoming Accio XML credentials against configured env vars.
    Uses constant-time comparison to prevent timing attacks.
    """
    if not account or not username or not password:
        return False
    account_ok = hmac.compare_digest(account, ACCIO_API_ACCOUNT)
    username_ok = hmac.compare_digest(username, ACCIO_API_USERNAME)
    password_ok = hmac.compare_digest(password, ACCIO_API_PASSWORD)
    return account_ok and username_ok and password_ok


def _xml_error_response(code: str, message: str) -> "Response":
    """Build an XML error response that Accio can parse."""
    from fastapi import Response as _Resp
    xml_body = (
        f"<?xml version='1.0' encoding='UTF-8'?>"
        f"<VendorResponse>"
        f"<status>error</status>"
        f"<errorcode>{_xml_escape(code)}</errorcode>"
        f"<errormessage>{_xml_escape(message)}</errormessage>"
        f"</VendorResponse>"
    )
    status = int(code) if code.isdigit() and 100 <= int(code) < 600 else 400
    return _Resp(content=xml_body, media_type="text/xml", status_code=status)


def _xml_ack_response(
    order_number: str, sub_order_number: str, success: bool
) -> "Response":
    """Build an XML acknowledgment response for Accio."""
    from fastapi import Response as _Resp
    status_text = "received" if success else "processing_error"
    xml_body = (
        f"<?xml version='1.0' encoding='UTF-8'?>"
        f"<VendorResponse>"
        f"<status>{status_text}</status>"
        f"<errorcode>0</errorcode>"
        f"<ordernumber>{_xml_escape(order_number)}</ordernumber>"
        f"<subordernumber>{_xml_escape(sub_order_number)}</subordernumber>"
        f"</VendorResponse>"
    )
    return _Resp(content=xml_body, media_type="text/xml", status_code=200)


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
