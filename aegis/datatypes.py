from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any
from typing import TypedDict

from aegis.utils import snake_case_response


class CveReference(TypedDict):
    type: str
    url: str


class CvePackage(TypedDict):
    name: str
    ecosystem: str
    purl: str


class CveEvent(TypedDict):
    introduced: str
    fixed: str


class CveRange(TypedDict):
    type: str
    events: list[CveEvent]


class CveAffected(TypedDict):
    package: CvePackage
    ranges: list[CveRange]
    versions: list[str]
    database_specific: dict[str, Any]


class CveSeverity(TypedDict):
    type: str
    score: str


class PackageVersionKey(TypedDict):
    system: str
    name: str
    version: str


class PackageLink(TypedDict):
    label: str
    url: str


class PackageProjectKey(TypedDict):
    id: str


class PackageAdvisoryKey(TypedDict):
    id: str


@snake_case_response
class PackageRelatedProject(TypedDict):
    projectKey: PackageProjectKey
    relationProvenance: str
    relationType: str


@snake_case_response
class PackageResponseData(TypedDict):
    versionKey: PackageVersionKey
    publishedAt: str
    isDefault: bool
    licenses: list[str]
    advisoryKeys: list[PackageAdvisoryKey]
    links: list[PackageLink]
    slsaProvenances: list
    registries: list[str]
    relatedProjects: list[PackageRelatedProject]


@snake_case_response
class VulnerabilityResponseData(TypedDict):
    advisoryKey: PackageAdvisoryKey
    url: str
    title: str
    aliases: list[str]
    cvss3Score: float
    cvss3Vector: str


class OsvCveResponseData(TypedDict, total=False):
    id: str
    details: str
    aliases: list[str]
    modified: str
    published: str
    references: list[CveReference]
    affected: list[CveAffected]
    schema_version: str
    severity: list[CveSeverity]


@snake_case_response
class MitreCveResponseData(TypedDict, total=False):
    id: str
    details: str
    severity: str
    published: str


class Package(TypedDict):
    package_name: str
    package_version: str


class Packagers(Enum):
    poetry = "poetry.lock"
    pipenv = "pipenv.lock"
    requirements_txt = "requirements.txt"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class PackageResult(Package, total=False):
    ids: list[str]
    description: str
    discovery_date: datetime
    affected_versions: list[str]
    score: Decimal
    level: Severity
    descriptions: list[str]


class Result(TypedDict):
    project: str
    is_vulnerable: bool
    has_critical: bool
    report: list[PackageResult]
