from datetime import UTC
from datetime import datetime
from pathlib import Path

import tablib

from datatypes import Result


def generate_report(project: str, all_packages: Result) -> None:
    """Generates a report of the vulnerabilities."""
    data = tablib.Dataset()
    data.headers = [
        "Project",
        "Is Vulnerable",
        "Has Critical",
        "Package Name",
        "Package Version",
        "CVE ID",
        "Description",
        "Discovery Date",
        "Affected Versions",
        "Score",
        "Severity",
        "Descriptions",
    ]

    for package in all_packages.values():
        for report in package["report"]:
            data.append(
                [
                    package["project"],
                    package["is_vulnerable"],
                    package["has_critical"],
                    report["package_name"],
                    report["package_version"],
                    report["ids"],
                    report["description"],
                    report["discovery_date"],
                    report["affected_versions"],
                    report["score"],
                    report["level"],
                    report["descriptions"],
                ],
            )

    unix_timestamp = str(int(datetime.now(tz=UTC).timestamp()))
    with open(Path.cwd() / "reports" / f"{unix_timestamp}-{project}.html", "w") as f:
        f.write(data.export("html"))
