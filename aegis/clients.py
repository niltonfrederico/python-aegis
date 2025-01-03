import json
import logging
import shlex
import subprocess

from base64 import b64decode
from dataclasses import dataclass
from typing import Literal

import requests

from aegis.datatypes import MitreCveResponseData
from aegis.datatypes import OsvCveResponseData
from aegis.datatypes import PackageResponseData
from aegis.datatypes import Packagers
from aegis.datatypes import VulnerabilityResponseData


logger = logging.getLogger("aegis")

FILENAME_PLACEHOLDER = ":filename"


def generate_endpoint_url(
    api_url: str,
    endpoint: str,
    version: str,
    **kwargs: str,
) -> str:
    """Generates the endpoint URL by replacing placeholders."""
    url = api_url + endpoint.replace(":api_version", version)
    for key, value in kwargs.items():
        url = url.replace(f":{key}", value)
    logger.debug("Generated URL: %s", url)
    return url


@dataclass
class DepsDevClientConfig:
    api_url: str = "https://api.deps.dev"
    version: str = "/v3"

    package_endpoint: str = (
        ":api_version/systems/PYPI/packages/:package_name/versions/:package_version"
    )
    vulnerability_endpoint: str = ":api_version/advisories/:cve"

    def package_endpoint_url(self, package_name: str, version: str) -> str:
        return generate_endpoint_url(
            self.api_url,
            self.package_endpoint,
            self.version,
            package_name=package_name,
            package_version=version,
        )

    def vulnerability_endpoint_url(self, cve: str) -> str:
        return generate_endpoint_url(
            self.api_url,
            self.vulnerability_endpoint,
            self.version,
            cve=cve,
        )


@dataclass
class MitreOrgClient:
    api_url: str = "https://cveawg.mitre.org/api"
    api_version: Literal[""] = ""
    cve_data_endpoint: str = "/cve/:cve"

    def cve_data_endpoint_url(self, cve: str) -> str:
        return generate_endpoint_url(
            self.api_url,
            self.cve_data_endpoint,
            self.api_version,
            cve=cve,
        )


@dataclass
class OsvClientConfig:
    api_url: str = "https://api.osv.dev"
    version: str = "/v1"

    cve_data_endpoint: str = ":api_version/vulns/:cve"

    def cve_data_endpoint_url(self, cve: str) -> str:
        return generate_endpoint_url(
            self.api_url,
            self.cve_data_endpoint,
            self.version,
            cve=cve,
        )


def get_package_info(package_name: str, version: str) -> PackageResponseData:
    """Fetches package information from the Deps.Dev API."""
    url = DepsDevClientConfig().package_endpoint_url(package_name, version)

    # Make a request to the API
    response = requests.get(url, timeout=5)
    response.raise_for_status()

    # Parse the response
    return PackageResponseData(**response.json())


def get_vulnerability_info(cve: str) -> VulnerabilityResponseData:
    """Fetches vulnerability information from the Deps.Dev API."""
    url = DepsDevClientConfig().vulnerability_endpoint_url(cve)

    # Make a request to the API
    response = requests.get(url, timeout=5)
    response.raise_for_status()

    # Parse the response
    return VulnerabilityResponseData(**response.json())


def get_cve_info_from_osv(cve: str) -> OsvCveResponseData:
    """Fetches CVE information from the OSV API."""
    url = OsvClientConfig().cve_data_endpoint_url(cve)

    # Make a request to the API
    response = requests.get(url, timeout=5)
    response.raise_for_status()

    # Parse the response
    return OsvCveResponseData(**response.json())


def get_cve_info_from_mitre(cve: str) -> MitreCveResponseData:
    url = MitreOrgClient().cve_data_endpoint_url(cve)

    # Make a request to the API
    response = requests.get(url, timeout=5)
    response.raise_for_status()

    # Parse the response
    response_json = response.json()
    metrics = response_json["containers"]["adp"][0]["metrics"]
    cvss_v3_1 = next(
        (
            metric["cvssV3_1"]["vectorString"]
            for metric in metrics
            if "cvssV3_1" in metric
        ),
        None,
    )

    return MitreCveResponseData(
        id=response_json["cveMetadata"]["cveId"],
        details=response_json["containers"]["cna"]["descriptions"][0]["value"],
        severity=cvss_v3_1,
        published=response_json["cveMetadata"]["datePublished"],
    )


def _run_process_and_return(
    command: list[str],
) -> str | bool:
    """
    Run a process and return the output.

    Args:
        command: Command to run
    """
    try:
        return subprocess.check_output(  # noqa: S603
            [shlex.quote(part) for part in command],
            text=True,
        ).strip()

    except subprocess.CalledProcessError:
        logger.exception("Error running command")
        return False


def does_repository_exist(owner: str, repo: str) -> bool:
    """
    Check if a repository exists on GitHub.

    Args:
        owner: Repository owner
        repo: Repository name
    """
    command = [
        "gh",
        "api",
        f"repos/{owner}/{repo}",
    ]

    return bool(_run_process_and_return(command))


def get_github_file(
    owner: str,
    repo: str,
) -> tuple[bool, str]:
    """
    Get file content using gh api command.

    Args:
        owner: Repository owner
        repo: Repository name
        path: Path to file
        branch: Branch name
    """
    base_command = [
        "gh",
        "api",
        f"repos/{owner}/{repo}/contents/{FILENAME_PLACEHOLDER}",
    ]

    filenames = [Packagers.poetry, Packagers.pipenv, Packagers.requirements_txt]

    for filename in filenames:
        command = base_command.copy()
        command[-1] = command[-1].replace(":filename", filename.value)

        if response := _run_process_and_return(command):
            return filename, b64decode(json.loads(response)["content"]).decode()

    error_message = "No lock file found in the repository."
    raise FileNotFoundError(error_message)
