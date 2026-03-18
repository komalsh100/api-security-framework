"""
scanner.py
----------
Main orchestrator for the API Security Testing Framework.

Usage:
  python scanner.py                          # uses config.yml defaults
  python scanner.py --config my-config.yml  # custom config
  python scanner.py --url http://localhost:5000 --mode external

Flow:
  1. Load config
  2. Start target app if mode=demo
  3. Connect to ZAP
  4. Configure auth (JWT / session)
  5. Spider the target
  6. Run ZAP active scan
  7. Run manual OWASP API Top 10 tests
  8. Generate HTML + JSON report
"""

import argparse
import logging
import os
import subprocess
import sys
import time

import yaml
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

try:
    from zapv2 import ZAPv2
    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False
    logger.warning("python-owasp-zap-v2.4 not installed. ZAP scan will be skipped.")

from auth import AuthHandler
from test_cases import OWASPAPITests
from report import generate_report


def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def start_demo_app(port: int = 5000):
    logger.info("Starting demo target app on port %d ...", port)
    proc = subprocess.Popen(
        [sys.executable, "target_app/app.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(20):
        try:
            requests.get(f"http://localhost:{port}/api/health", timeout=1)
            logger.info("Demo app is ready.")
            return proc
        except Exception:
            time.sleep(0.5)
    logger.error("Demo app failed to start within 10 seconds.")
    proc.terminate()
    sys.exit(1)


def connect_to_zap(host: str, port: int, api_key: str):
    if not ZAP_AVAILABLE:
        return None
    proxy = f"http://{host}:{port}"
    zap = ZAPv2(apikey=api_key, proxies={"http": proxy, "https": proxy})
    try:
        zap.core.version
        logger.info("Connected to ZAP at %s", proxy)
        return zap
    except Exception as e:
        logger.warning("Could not connect to ZAP: %s. ZAP scan will be skipped.", e)
        return None


def run_zap_scan(zap, target_url: str, config: dict) -> list:
    scan_cfg = config.get("scan", {})
    threshold = scan_cfg.get("severity_threshold", "medium")
    timeout = scan_cfg.get("scan_timeout", 120)
    SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_rank = SEVERITY_RANK.get(threshold.lower(), 2)

    logger.info("Starting ZAP spider on %s ...", target_url)
    scan_id = zap.spider.scan(target_url)
    start = time.time()
    while int(zap.spider.status(scan_id)) < 100:
        if time.time() - start > timeout:
            logger.warning("Spider timed out.")
            break
        time.sleep(2)
    logger.info("Spider complete. %d URLs found.", len(zap.spider.results(scan_id)))

    if scan_cfg.get("active_scan", True):
        logger.info("Starting ZAP active scan ...")
        ascan_id = zap.ascan.scan(target_url)
        start = time.time()
        while int(zap.ascan.status(ascan_id)) < 100:
            if time.time() - start > timeout:
                logger.warning("Active scan timed out.")
                break
            logger.info("Active scan progress: %s%%", zap.ascan.status(ascan_id))
            time.sleep(5)
        logger.info("Active scan complete.")

    all_alerts = zap.core.alerts(baseurl=target_url)
    filtered = [
        a for a in all_alerts
        if SEVERITY_RANK.get(a.get("risk", "informational").lower(), 0) >= min_rank
    ]
    logger.info("ZAP found %d alerts (%d above threshold).", len(all_alerts), len(filtered))
    return filtered


def main():
    parser = argparse.ArgumentParser(description="API Security Testing Framework")
    parser.add_argument("--config", default="config.yml", help="Path to config.yml")
    parser.add_argument("--url", help="Override target URL")
    parser.add_argument("--mode", choices=["demo", "external"], help="Override scan mode")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.url:
        config["target"]["url"] = args.url
        config["target"]["mode"] = "external"
    if args.mode:
        config["target"]["mode"] = args.mode

    mode = config["target"]["mode"]
    target_url = config["target"]["url"] if mode == "external" else "http://localhost:5000"

    demo_proc = None
    if mode == "demo":
        demo_proc = start_demo_app()

    zap_cfg = config.get("zap", {})
    zap = connect_to_zap(
        host=zap_cfg.get("host", "localhost"),
        port=zap_cfg.get("port", 8090),
        api_key=zap_cfg.get("api_key", "changeme"),
    )

    auth_headers = {}
    if zap:
        auth_handler = AuthHandler(zap, config)
        auth_handler.configure()
        auth_headers = auth_handler.get_auth_headers()
    else:
        class _FakeZap:
            class replacer:
                @staticmethod
                def add_rule(**kwargs): pass
        ah = AuthHandler(_FakeZap(), config)
        auth_headers = ah.get_auth_headers()

    zap_alerts = []
    if zap:
        zap_alerts = run_zap_scan(zap, target_url, config)
    else:
        logger.info("Skipping ZAP scan - running manual tests only.")

    logger.info("Running manual OWASP API Top 10 tests against %s ...", target_url)
    threshold = config.get("scan", {}).get("severity_threshold", "medium")
    tester = OWASPAPITests(target_url, auth_headers, threshold)
    manual_results = tester.run_all()

    fail_count = sum(1 for r in manual_results if not r.passed)
    logger.info("Manual tests complete - %d failed, %d passed.",
                fail_count, len(manual_results) - fail_count)

    report_cfg = config.get("report", {})
    output_path = os.path.join(report_cfg.get("output_dir", "reports"), report_cfg.get("filename", "security_report.html"))
    report_path = generate_report(zap_alerts, manual_results, target_url, output_path)
    logger.info("Report saved to: %s", report_path)

    if demo_proc:
        demo_proc.terminate()
        logger.info("Demo app stopped.")

    critical_count = sum(
        1 for a in zap_alerts if a.get("risk", "").lower() in ("critical", "high")
    ) + sum(
        1 for r in manual_results if not r.passed and r.severity in ("critical", "high")
    )

    if critical_count > 0:
        logger.warning("Found %d critical/high issues. Failing build.", critical_count)
        sys.exit(1)

    logger.info("Scan complete. No critical/high issues found.")


if __name__ == "__main__":
    main()
