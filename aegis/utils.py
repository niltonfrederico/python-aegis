from collections.abc import Generator
from typing import Any
from typing import get_type_hints

from cvss import CVSS2
from cvss import CVSS3
from cvss import CVSS4


CVSS_SEVERITY_DEFINITIONS = {
    "AV": {
        "definition": "Attack Vector (AV)",
        "N": "Network (AV-N)",
        "A": "Adjacent (AV-A)",
        "L": "Local (AV-L)",
        "P": "Physical (AV-P)",
    },
    "AC": {
        "definition": "Attack Complexity (AC)",
        "H": "High (AC-H)",
        "L": "Low (AC-L)",
    },
    "PR": {
        "definition": "Privileges Required (PR)",
        "H": "High (PR-H)",
        "L": "Low (PR-L)",
        "N": "None (PR-N)",
    },
    "UI": {
        "definition": "User Interaction (UI)",
        "N": "None (UI-N)",
        "R": "Required (UI-R)",
    },
    "S": {
        "definition": "Scope (S)",
        "U": "Unchanged (S-U)",
        "C": "Changed (S-C)",
    },
    "C": {
        "definition": "Confidentiality (C)",
        "H": "High (C-H)",
        "L": "Low (C-L)",
        "N": "None (C-N)",
    },
    "I": {
        "definition": "Integrity (I)",
        "H": "High (I-H)",
        "L": "Low (I-L)",
        "N": "None (I-N)",
    },
    "A": {
        "definition": "Availability (A)",
        "H": "High (A-H)",
        "L": "Low (A-L)",
        "N": "None (N-N)",
    },
}


def convert_camel_to_snake(s: str) -> str:
    """Convert camelCase to snake_case."""
    result = [s[0].lower()]
    for char in s[1:]:
        if char.isupper():
            result.extend(["_", char.lower()])
        else:
            result.append(char)
    return "".join(result)


def snake_case_response(cls: type[dict]) -> type[dict]:
    """Decorator to add camelCase support to TypedDict."""
    original_annotations = get_type_hints(cls)

    # Create a new class with the same name and bases
    class Wrapped(cls):
        def __init__(self, *_args: Any, **kwargs: Any) -> None:
            converted_kwargs = {}
            for key, value in kwargs.items():
                snake_key = convert_camel_to_snake(key)
                if snake_key in original_annotations:
                    converted_kwargs[snake_key] = value
            super().__init__(**converted_kwargs)

    Wrapped.__name__ = cls.__name__
    return Wrapped


def get_score_and_severity_from_cvss(
    vector: str,
) -> tuple[float, str, list[dict[str, str]]]:
    def fiendly_dict_definitions_from_vector(
        vector: str,
    ) -> Generator[tuple[str, str]]:
        (_, *vectors) = vector.split("/")

        for _vector in vectors:
            key, value = _vector.split(":")
            yield CVSS_SEVERITY_DEFINITIONS[key][
                "definition"
            ], CVSS_SEVERITY_DEFINITIONS[key][value]

    if vector.startswith("CVSS:3"):
        cvss = CVSS3(vector)
    elif vector.startswith("CVSS:4"):
        cvss = CVSS4(vector)
    elif vector.startswith("CVSS:2"):
        cvss = CVSS2(vector)
    else:
        error_message = "Invalid CVSS version"
        raise ValueError(error_message)

    score = cvss.as_json()

    return (
        score["baseScore"],
        score["baseSeverity"],
        list(fiendly_dict_definitions_from_vector(vector)),
    )
