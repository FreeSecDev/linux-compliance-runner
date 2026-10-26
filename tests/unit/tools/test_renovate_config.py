from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

CONFIG: Final[Path] = Path(__file__).resolve().parents[3] / ".renovaterc.json"
REGEX_KEYS: Final[frozenset[str]] = frozenset({"matchStrings", "extractVersionTemplate"})
SLASH_PATTERN: Final[re.Pattern[str]] = re.compile(r"!?/(?P<body>.+)/[a-z]*")
RE2_UNSUPPORTED: Final[re.Pattern[str]] = re.compile(
    r"(?<!\\)\(\?(?:[=!>]|<[=!])|\\[1-9]|\\k<|\\g[<{0-9]"
)


def regex_strings(node: object, key: str = "") -> Iterator[str]:
    """Yield every regular expression in a Renovate configuration tree."""
    if isinstance(node, dict):
        for child_key, child in cast("dict[str, object]", node).items():
            yield from regex_strings(child, child_key)
    elif isinstance(node, list):
        for child in cast("list[object]", node):
            yield from regex_strings(child, key)
    elif isinstance(node, str):
        if key in REGEX_KEYS:
            yield node
        elif (match := SLASH_PATTERN.fullmatch(node)) is not None:
            yield match.group("body")


def re2_problems(patterns: Iterator[str]) -> list[str]:
    return [pattern for pattern in patterns if RE2_UNSUPPORTED.search(pattern)]


def test_committed_config_uses_only_re2_compatible_regexes() -> None:
    config: object = json.loads(CONFIG.read_text(encoding="utf-8"))
    patterns = list(regex_strings(config))
    assert any("COSIGN_VERSION" in pattern for pattern in patterns)
    assert any(pattern.startswith("^tools/renovate/") for pattern in patterns)
    assert re2_problems(iter(patterns)) == []


@pytest.mark.parametrize(
    "pattern",
    [
        "VERSION := (?=\\d)(?<currentValue>\\S+)",
        "VERSION := (?!x)(?<currentValue>\\S+)",
        "(?<=v)(?<currentValue>\\S+)",
        "(?<!v)(?<currentValue>\\S+)",
        "(?>atomic)",
        "(?<q>['\"])value\\1",
        "(?<q>['\"])value\\k<q>",
    ],
)
def test_re2_incompatible_match_strings_are_rejected(pattern: str) -> None:
    config = {"customManagers": [{"matchStrings": [pattern]}]}
    assert re2_problems(regex_strings(config)) == [pattern]


@pytest.mark.parametrize("value", ["/(?=x)Makefile$/", "!/(?<!a)b/i"])
def test_re2_incompatible_slash_patterns_are_rejected(value: str) -> None:
    config = {"packageRules": [{"matchPackageNames": [value]}]}
    assert len(re2_problems(regex_strings(config))) == 1


@pytest.mark.parametrize(
    "pattern",
    [
        "GRYPE_VERSION := (?<currentValue>\\S+)\\nGRYPE_SHA256 := (?<currentDigest>[a-f0-9]{64})",
        "^v(?<version>.+)$",
        "literal \\(\\?=\\) parenthesis",
        "(?:non-capturing)(?i:flags)",
    ],
)
def test_re2_compatible_patterns_pass(pattern: str) -> None:
    config = {"customManagers": [{"matchStrings": [pattern], "extractVersionTemplate": pattern}]}
    assert re2_problems(regex_strings(config)) == []


def test_plain_strings_are_not_treated_as_regexes() -> None:
    config = {"description": "uses (?=lookahead) in prose", "labels": ["ci", "a/b"]}
    assert list(regex_strings(config)) == []
