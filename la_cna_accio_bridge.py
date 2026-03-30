#!/usr/bin/env python3
"""
Playwright Fallback Module for LA CNA Registry Lookup
======================================================

DISASTER RECOVERY ONLY — use this module if the LA site adds JavaScript
dependencies that break the primary HTTP POST pathway.

This module provides the same interface as the httpx-based LACNARegistryClient
but uses a headless Chromium browser via Playwright for form submission.

SECURITY: Same triple-layer SSN protections apply.
"""

from __future__ import annotations

import asyncio
import gc
import re
import time
from typing import Any, Optional

from la_cna_accio_bridge import (
    CertificationStatus,
    CNAResult,
    LookupMetrics,
    SecureSSN,
    _secure_zero_string,
    HTTP_TIMEOUT_SECONDS,
    LA_CNA_URL,
    MAX_CONCURRENT_LOOKUPS,
    MAX_RETRIES,
    RETRY_BASE_DELAY,
)

try:
    from playwright.async_api import async_playwright, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class LACNARegistryPlaywrightClient:
    """
    Playwright-based fallback for CNA lookups.

    Uses headless Chromium to:
      1. Navigate to the search form
      2. Fill SSN field (with dashes)
      3. Click Search
      4. Parse the results table
      5. Destroy all PII from memory and close the browser context
    """

    def __init__(self) -> None:
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError(
                "Playwright is required for fallback mode: "
                "pip install playwright && playwright install chromium"
            )
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_LOOKUPS)
        self._playwright = None
        self._browser = None

    async def _ensure_browser(self) -> None:
        """Lazily start the Playwright browser."""
        if self._browser is None:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--disable-background-networking",
                    "--disable-default-apps",
                    "--disable-sync",
                    "--disable-translate",
                    "--metrics-recording-only",
                    "--no-first-run",
                ],
            )

    async def close(self) -> None:
        """Shut down browser and Playwright."""
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

    async def lookup_by_ssn(
        self, ssn_holder: SecureSSN, order_number: str
    ) -> tuple[CNAResult, LookupMetrics]:
        """
        Perform a CNA lookup using Playwright headless browser.
        Same interface as LACNARegistryClient.lookup_by_ssn().
        """
        async with self._semaphore:
            start_time = time.monotonic()
            retry_count = 0

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
                except Exception:
                    retry_count = attempt + 1
                    if attempt < MAX_RETRIES - 1:
                        delay = RETRY_BASE_DELAY * (2 ** attempt)
                        await asyncio.sleep(delay)

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
        """Single Playwright-based lookup attempt."""
        await self._ensure_browser()

        # Each lookup gets a fresh browser context (no shared state/cookies)
        context = await self._browser.new_context(
            viewport={"width": 1280, "height": 720},
            java_script_enabled=True,
        )

        try:
            page = await context.new_page()
            page.set_default_timeout(HTTP_TIMEOUT_SECONDS * 1000)

            # Navigate to the search form
            await page.goto(LA_CNA_URL, wait_until="networkidle")

            # Fill SSN field (with dashes as required)
            ssn_formatted = ssn_holder.with_dashes()
            await page.fill("#txtSSNNum", ssn_formatted)

            # Immediately zero the formatted SSN
            _secure_zero_string(ssn_formatted)
            ssn_formatted = "\x00" * 11
            del ssn_formatted
            gc.collect()

            # Ensure Employee Type is CNA
            await page.select_option("#cboEmployeeType", "CNA")

            # Click Search and wait for response
            await page.click("#btnSearch")
            await page.wait_for_load_state("networkidle")

            # Extract the page HTML for parsing
            html = await page.content()

            # Clear the SSN field in the browser before closing
            await page.fill("#txtSSNNum", "")
            await page.evaluate('document.getElementById("txtSSNNum").value = ""')

        finally:
            # Always close the context (destroys all browser-side data)
            await context.close()
            gc.collect()

        # Parse using the same parser from the main module
        return _parse_playwright_results(html)

    async def __aenter__(self) -> "LACNARegistryPlaywrightClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()


def _parse_playwright_results(html: str) -> CNAResult:
    """Parse results HTML (same logic as LACNARegistryClient._parse_results)."""
    from la_cna_accio_bridge import LACNARegistryClient
    return LACNARegistryClient._parse_results(html)
