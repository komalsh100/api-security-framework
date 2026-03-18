"""
test_cases.py
-------------
Manual OWASP API Top 10 test scenarios executed via direct HTTP requests.
These complement ZAP's active scan with targeted logic checks that
automated scanners often miss (e.g. BOLA, mass assignment).
"""

import requests
import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    test_id: str
    name: str
    owasp_category: str
    severity: str           # critical | high | medium | low | info
    passed: bool
    detail: str
    endpoint: str
    method: str
    evidence: Optional[str] = None


class OWASPAPITests:
    """
    Runs targeted OWASP API Top 10 test cases against the target API.
    Each test method returns a TestResult.
    """

    SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def __init__(self, base_url: str, auth_headers: dict, threshold: str = "medium"):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Content-Type": "application/json", **auth_headers}
        self.threshold = threshold
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _above_threshold(self, severity: str) -> bool:
        return self.SEVERITY_ORDER.get(severity, 0) >= self.SEVERITY_ORDER.get(self.threshold, 0)

    # ── API1: Broken Object Level Authorization ───────────────────────────────

    def test_bola(self) -> TestResult:
        """
        Attempt to access another user's resource without authorization.
        Fetches user ID 2 while authenticated as user ID 1.
        """
        endpoint = "/api/users/2"
        try:
            r = self.session.get(self._url(endpoint), timeout=10)
            passed = r.status_code in (401, 403)
            return TestResult(
                test_id="API1-001",
                name="Broken Object Level Authorization (BOLA)",
                owasp_category="API1:2023",
                severity="critical",
                passed=passed,
                detail="Endpoint returned another user's data without authorization check." if not passed
                       else "Endpoint correctly denied cross-user access.",
                endpoint=endpoint,
                method="GET",
                evidence=f"HTTP {r.status_code} — {r.text[:200]}" if not passed else None,
            )
        except Exception as e:
            return self._error_result("API1-001", "BOLA", endpoint, "GET", str(e))

    # ── API2: Broken Authentication ───────────────────────────────────────────

    def test_broken_auth_no_token(self) -> TestResult:
        """Access a protected endpoint with no auth token."""
        endpoint = "/api/users/1"
        try:
            r = requests.get(self._url(endpoint), timeout=10)  # no auth headers
            passed = r.status_code in (401, 403)
            return TestResult(
                test_id="API2-001",
                name="Broken Authentication — No Token",
                owasp_category="API2:2023",
                severity="high",
                passed=passed,
                detail="Endpoint accessible without any authentication token." if not passed
                       else "Endpoint correctly requires authentication.",
                endpoint=endpoint,
                method="GET",
                evidence=f"HTTP {r.status_code}" if not passed else None,
            )
        except Exception as e:
            return self._error_result("API2-001", "Broken Auth", endpoint, "GET", str(e))

    def test_broken_auth_invalid_token(self) -> TestResult:
        """Access a protected endpoint with a tampered/invalid JWT."""
        endpoint = "/api/users/1"
        bad_headers = {**self.headers, "Authorization": "Bearer invalidsignature.tampered.token"}
        try:
            r = requests.get(self._url(endpoint), headers=bad_headers, timeout=10)
            passed = r.status_code in (401, 403)
            return TestResult(
                test_id="API2-002",
                name="Broken Authentication — Invalid Token",
                owasp_category="API2:2023",
                severity="high",
                passed=passed,
                detail="Endpoint accepted an invalid/tampered token." if not passed
                       else "Endpoint correctly rejected invalid token.",
                endpoint=endpoint,
                method="GET",
                evidence=f"HTTP {r.status_code}" if not passed else None,
            )
        except Exception as e:
            return self._error_result("API2-002", "Broken Auth Invalid Token", endpoint, "GET", str(e))

    # ── API3: Broken Object Property Level Authorization ──────────────────────

    def test_mass_assignment(self) -> TestResult:
        """Attempt to elevate privileges via mass assignment (role field)."""
        endpoint = "/api/users/1"
        payload = {"role": "admin"}
        try:
            r = self.session.put(self._url(endpoint), json=payload, timeout=10)
            if r.status_code == 200:
                data = r.json()
                passed = data.get("role") != "admin"
            else:
                passed = True
            return TestResult(
                test_id="API3-001",
                name="Broken Object Property Level Auth — Mass Assignment",
                owasp_category="API3:2023",
                severity="high",
                passed=passed,
                detail="API accepted role escalation via mass assignment." if not passed
                       else "API correctly rejected or ignored privileged field.",
                endpoint=endpoint,
                method="PUT",
                evidence=f"role set to: {r.json().get('role')}" if not passed else None,
            )
        except Exception as e:
            return self._error_result("API3-001", "Mass Assignment", endpoint, "PUT", str(e))

    # ── API5: Broken Function Level Authorization ─────────────────────────────

    def test_admin_endpoint_access(self) -> TestResult:
        """Access admin endpoint as a regular user."""
        endpoint = "/api/admin/users"
        try:
            r = self.session.get(self._url(endpoint), timeout=10)
            passed = r.status_code in (401, 403)
            return TestResult(
                test_id="API5-001",
                name="Broken Function Level Authorization — Admin Endpoint",
                owasp_category="API5:2023",
                severity="critical",
                passed=passed,
                detail="Admin endpoint accessible without admin role." if not passed
                       else "Admin endpoint correctly restricted.",
                endpoint=endpoint,
                method="GET",
                evidence=f"HTTP {r.status_code} returned {len(r.json()) if r.status_code == 200 else 0} records" if not passed else None,
            )
        except Exception as e:
            return self._error_result("API5-001", "Admin Endpoint Access", endpoint, "GET", str(e))

    def test_sensitive_export(self) -> TestResult:
        """Access unauthenticated data export endpoint."""
        endpoint = "/api/admin/export"
        try:
            r = requests.get(self._url(endpoint), timeout=10)  # no auth
            passed = r.status_code in (401, 403)
            return TestResult(
                test_id="API5-002",
                name="Broken Function Level Authorization — Unauthenticated Export",
                owasp_category="API5:2023",
                severity="critical",
                passed=passed,
                detail="Sensitive export endpoint accessible without any authentication." if not passed
                       else "Export endpoint correctly requires authentication.",
                endpoint=endpoint,
                method="GET",
                evidence=f"HTTP {r.status_code}" if not passed else None,
            )
        except Exception as e:
            return self._error_result("API5-002", "Unauthenticated Export", endpoint, "GET", str(e))

    # ── API8: Security Misconfiguration ──────────────────────────────────────

    def test_verbose_errors(self) -> TestResult:
        """Trigger an error and check if stack trace or internal info leaks."""
        endpoint = "/api/users/99999"
        try:
            r = self.session.get(self._url(endpoint), timeout=10)
            body = r.text.lower()
            leaks = any(kw in body for kw in ["traceback", "exception", "sqlalchemy", "werkzeug", "line "])
            passed = not leaks
            return TestResult(
                test_id="API8-001",
                name="Security Misconfiguration — Verbose Error Messages",
                owasp_category="API8:2023",
                severity="medium",
                passed=passed,
                detail="API leaks internal stack trace or framework details in error responses." if not passed
                       else "Error responses do not leak internal details.",
                endpoint=endpoint,
                method="GET",
                evidence=r.text[:300] if not passed else None,
            )
        except Exception as e:
            return self._error_result("API8-001", "Verbose Errors", endpoint, "GET", str(e))

    # ── Runner ────────────────────────────────────────────────────────────────

    def run_all(self) -> List[TestResult]:
        """Run all test cases and return results above the severity threshold."""
        tests = [
            self.test_bola,
            self.test_broken_auth_no_token,
            self.test_broken_auth_invalid_token,
            self.test_mass_assignment,
            self.test_admin_endpoint_access,
            self.test_sensitive_export,
            self.test_verbose_errors,
        ]
        results = []
        for test_fn in tests:
            try:
                result = test_fn()
                if self._above_threshold(result.severity):
                    results.append(result)
                    status = "PASS" if result.passed else "FAIL"
                    logger.info("[%s] %s — %s", status, result.test_id, result.name)
            except Exception as e:
                logger.error("Test %s crashed: %s", test_fn.__name__, e)
        return results

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _error_result(self, test_id, name, endpoint, method, error_msg) -> TestResult:
        return TestResult(
            test_id=test_id,
            name=name,
            owasp_category="N/A",
            severity="info",
            passed=False,
            detail=f"Test could not complete: {error_msg}",
            endpoint=endpoint,
            method=method,
        )
