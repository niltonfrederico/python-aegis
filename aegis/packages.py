from typing import Literal

import toml

from aegis.datatypes import Package
from aegis.datatypes import Packagers


def get_packages_from_poetry_lock(file_string: str) -> list[Package]:
    poetry_lock = toml.loads(file_string)

    return [
        Package(package_name=package["name"], package_version=package["version"])
        for package in poetry_lock["package"]
    ]


def get_packages_from_pipenv_lock(file_string: str) -> list[Package]:
    pipenv_lock = toml.loads(file_string)

    # Remove all keys that start with _
    for key in list(pipenv_lock.keys()):
        if key.startswith("_"):
            del pipenv_lock[key]

    # Merge all dict keys into a single dict
    merged_packages = {}
    for _group, packages in pipenv_lock.items():
        for name, version in packages.items():
            merged_packages[name] = version

    return [
        Package(package_name=name, package_version=version)
        for name, version in merged_packages.items()
    ]


def get_packages_from_requirements_txt(file_string: str) -> list[Package]:
    requirements_txt = file_string.split("\n")

    return [
        Package(
            package_name=package.split("==")[0],
            package_version=package.split("==")[1],
        )
        for package in requirements_txt
        if not package.startswith("#")
    ]


def get_packages(
    package_type: Literal["poetry", "pipenv", "requirements.txt"],
    requirements_string: str,
) -> list[Package]:
    match package_type:
        case Packagers.poetry:
            return get_packages_from_poetry_lock(requirements_string)
        case Packagers.pipenv:
            return get_packages_from_pipenv_lock(requirements_string)
        case Packagers.requirements_txt:
            return get_packages_from_requirements_txt(requirements_string)
        case _:
            error_message = "Invalid package type."
            raise ValueError(error_message)
