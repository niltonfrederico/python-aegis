import argparse
import logging
import re
import shutil
import sys

from decimal import Decimal

from clients import get_cve_info
from clients import get_github_file
from clients import get_package_info
from datatypes import Package
from datatypes import PackageResult
from datatypes import Result
from packages import get_packages
from requests.exceptions import HTTPError
from utils import get_score_and_severity_from_cvss

from reports import generate_report


# Set format for logger [YYYY-MM-DD HH:MM:SS] [LEVEL] [MESSAGE]
logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    level=logging.INFO,
    handlers=[logging.StreamHandler()],
)

# Create logger that prints to stdout
logger = logging.getLogger("aegis")


EMPTY_ARG = "__empty__"


# Argument Parser
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Aegis is a tool to help you manage your dependencies.",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode.",
        default=False,
    )

    parser.add_argument(
        "repository",
        nargs="?",
        type=_validate_repository,
        help="Repository name (owner/repository).",
        default=EMPTY_ARG,
    )

    return parser.parse_args()


def _validate_repository(value: str | None) -> str:
    if value == EMPTY_ARG:
        error_message = "Repository is required."
        raise argparse.ArgumentTypeError(error_message)

    if "/" not in value:
        error_message = "Repository must be in the format owner/repository."
        raise argparse.ArgumentTypeError(error_message)

    return value


def get_cve_if_not_cve(advisory_key: str) -> str:
    logger.info("get_cve_if_not_cve: %s", advisory_key)
    if not advisory_key.startswith("CVE"):
        vulnerability_info = get_cve_info(advisory_key)
        return next(
            (
                alias
                for alias in vulnerability_info.get("aliases", [])
                if alias.startswith("CVE")
            ),
            advisory_key,
        )
    return advisory_key


def parse_version_ranges(text: str) -> list[str]:
    """
    Parse version ranges from CVE text and format them.

    Args:
        text: CVE description text

    Returns:
        List of version ranges in format ">=lowest_version<=highest_version"
    """
    # Pattern to match "X.Y before X.Y.Z"
    pattern = r"(\d+\.\d+)(?:\.\d+)? before (\d+\.\d+\.\d+)"
    matches = re.finditer(pattern, text)

    ranges = []
    for match in matches:
        base, highest = match.groups()
        # Construct lowest version by adding .0
        lowest = f"{base}.0"
        ranges.append(f">={lowest}<={highest}")

    return ranges


def process_package(package: Package) -> list[PackageResult]:
    package_name, package_version = package.values()
    logger.info("Processing package %s %s", package_name, package_version)

    try:
        package_data = get_package_info(package_name, package_version)
        logger.debug("Package data: %s", package_data)
    except HTTPError as exc:
        logger.warning("Error getting package data: %s", exc.response.status_code)
        return []

    advisory_keys = [key["id"] for key in package_data.get("advisoryKeys", [])]

    vulnerabilities = []
    for advisory_key in advisory_keys:
        logger.debug("Advisory key: %s", advisory_key)
        cve = get_cve_if_not_cve(advisory_key)

        if not cve:
            logger.warning("No CVE found for advisory key: %s", advisory_key)
            continue

        vulnerability_info = get_cve_info(cve)
        logger.debug("Vulnerability info: %s", vulnerability_info)

        affected_versions = parse_version_ranges(vulnerability_info["details"])

        if "severity" in vulnerability_info:
            score, severity, descriptions = get_score_and_severity_from_cvss(
                vulnerability_info["severity"][-1]["score"],
            )
        elif "database_specific" in vulnerability_info:
            score = Decimal("0.0")
            severity = vulnerability_info["database_specific"]["severity"]
            descriptions = []
        else:
            logger.warning("No CVSS score found for CVE %s", cve)
            score = Decimal("0.0")
            severity = "UNKNOWN"
            descriptions = []

        aliases = vulnerability_info.get("aliases", [])

        package_result = PackageResult(
            package_name=package_name,
            package_version=package_version,
            ids=aliases,
            description=vulnerability_info["details"],
            discovery_date=vulnerability_info["published"],
            affected_versions=affected_versions,
            score=score,
            level=severity,
            descriptions=descriptions,
        )

        logger.debug("Package result: %s", package_result)

        vulnerabilities.append(package_result)

    return vulnerabilities


def aegis() -> None:
    # > Check if github cli is installed
    if not shutil.which("gh"):
        logger.warning("Please install the GitHub CLI (gh) before running this script.")
        sys.exit(1)

    args = parse_args()

    # Set log level to debug if debug flag is set
    if args.debug:
        logger.setLevel(logging.DEBUG)

    logger.debug(args)
    logger.info("Checking dependencies safety for repository %s", args.repository)

    owner, repository = args.repository.split("/")

    lock_type, dependency_file = get_github_file(owner, repository)
    logger.info("Lock type: %s", lock_type)
    logger.debug("Dependency file: %s", dependency_file)

    packages = get_packages(lock_type, dependency_file)
    logger.debug("Packages: %s", packages)

    all_packages = {}
    for package in packages:
        vulnerabilities = process_package(package)

        all_packages[package["package_name"]] = Result(
            project=package["package_name"],
            is_vulnerable=bool(vulnerabilities),
            has_critical=any(
                result["level"] == "CRITICAL" for result in vulnerabilities
            ),
            report=vulnerabilities,
        )

    generate_report(repository, all_packages)
