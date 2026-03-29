#!/usr/bin/env python3
"""
Parser Test Suite â verifies HTML parsing of LA CNA Registry responses.

Uses static HTML fixtures to test all result scenarios without
making network calls or handling any PII.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from la_cna_accio_bridge import CertificationStatus, LACNARegistryClient


# ââ HTML Fixtures ââ

CERTIFIED_SINGLE_RESULT = """
<html><body>
<table id="dgvList" border="1">
<tr><td>Name (CNA)</td><td>Certification Number</td><td>Certified From-To</td>
<td>Original Certification</td><td>Status</td><td>Retest Required By</td></tr>
<tr><td>Doe, Jane A</td><td>12345</td><td>01/01/2025 - 01/01/2027</td>
<td>03/15/2010</td><td>Certified</td><td> </td></tr>
</table>
</body></html>
"""

NOT_CERTIFIED_RESULT = """
<html><body>
<table id="dgvList" border="1">
<tr><td>Name (CNA)</td><td>Certification Number</td><td>Certified From-To</td>
<td>Original Certification</td><td>Status</td><td>Retest Required By</td></tr>
<tr><td>Smith, John</td><td>67890</td><td>01/01/2020 - 01/01/2022</td>
<td>06/01/2015</td><td>Not Certified</td><td>01/01/2024</td></tr>
</table>
</body></html>
"""

CALL_REGISTRY_RESULT = """
<html><body>
<table id="dgvList" border="1">
<tr><td>Name (CNA)</td><td>Certification Number</td><td>Certified From-To</td>
<td>Original Certification</td><td>Status</td><td>Retest Required By</td></tr>
<tr><td>Brown, Alice</td><td>11111</td><td>08/22/1994 - 08/22/1994</td>
<td>06/07/1993</td><td>Call CNA Registry</td><td> </td></tr>
</table>
</body></html>
"""

MULTIPLE_RESULTS = """
<html><body>
<table id="dgvList" border="1">
<tr><td>Name (CNA)</td><td>Certification Number</td><td>Certified From-To</td>
<td>Original Certification</td><td>Status</td><td>Retest Required By</td></tr>
<tr><td>Garcia, Maria</td><td>22222</td><td>01/01/2025 - 01/01/2027</td>
<td>04/04/1995</td><td>Certified</td><td> </td></tr>
<tr><td>Garcia, Maria</td><td>33333</td><td>01/01/2019 - 01/01/2021</td>
<td>04/04/1995</td><td>Not Certified</td><td>01/01/2023</td></tr>
</table>
</body></html>
"""

NO_DATA_RESULT = """
<html><body>
<div>No Data. Verify the correct employee type was selected</div>
</body></html>
"""

EMPTY_TABLE_RESULT = """
<html><body>
<table id="dgvList" border="1">
<tr><td>Name (CNA)</td><td>Certification Number</td><td>Certified From-To</td>
<td>Original Certification</td><td>Status</td><td>Retest Required By</td></tr>
<tr><td></td><td></td><td></td><td></td><td></td><td></td></tr>
</table>
</body></html>
"""


class TestResultParser:
    """Tests for LACNARegistryClient._parse_results()."""

    def test_certified_single_match(self):
        result = LACNARegistryClient._parse_results(CERTIFIED_SINGLE_RESULT)
        assert result.status == CertificationStatus.CERTIFIED
        assert result.name == "Doe, Jane A"
        assert result.certification_number == "12345"
        assert result.certified_from == "01/01/2025"
        assert result.certified_to == "01/01/2027"
        assert result.original_certification_date == "03/15/2010"
        assert result.retest_required_by == ""
        assert result.multiple_matches is False
        assert result.match_count == 1

    def test_not_certified(self):
        result = LACNARegistryClient._parse_results(NOT_CERTIFIED_RESULT)
        assert result.status == CertificationStatus.NOT_CERTIFIED
        assert result.name == "Smith, John"
        assert result.certification_number == "67890"
        assert result.retest_required_by == "01/01/2024"

    def test_call_registry(self):
        result = LACNARegistryClient._parse_results(CALL_REGISTRY_RESULT)
        assert result.status == CertificationStatus.CALL_REGISTRY
        assert result.name == "Brown, Alice"

    def test_multiple_results_uses_first(self):
        result = LACNARegistryClient._parse_results(MULTIPLE_RESULTS)
        assert result.status == CertificationStatus.CERTIFIED
        assert result.name == "Garcia, Maria"
        assert result.certification_number == "22222"
        assert result.multiple_matches is True
        assert result.match_count == 2

    def test_no_data_response(self):
        result = LACNARegistryClient._parse_results(NO_DATA_RESULT)
        assert result.status == CertificationStatus.NOT_FOUND
        assert result.name == ""
        assert result.certification_number == ""

    def test_empty_table(self):
        result = LACNARegistryClient._parse_results(EMPTY_TABLE_RESULT)
        assert result.status == CertificationStatus.NOT_FOUND

    def test_completely_empty_html(self):
        result = LACNARegistryClient._parse_results("")
        assert result.status == CertificationStatus.NOT_FOUND

    def test_malformed_html(self):
        result = LACNARegistryClient._parse_results("<html><body>Random content</body></html>")
        assert result.status == CertificationStatus.NOT_FOUND
