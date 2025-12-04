# -*- coding: utf-8 -*-
#
# Minimal subset of the semver library used for offline test execution.

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Version:
    major: int
    minor: int = 0
    patch: int = 0
    prerelease: Optional[str] = None
    build: Optional[str] = None

    @classmethod
    def parse(cls, version: str, optional_minor_and_patch: bool = False) -> "Version":
        pattern = (
            r"^(?P<major>0|[1-9]\d*)"
            r"(?:\.(?P<minor>0|[1-9]\d*))?"
            r"(?:\.(?P<patch>0|[1-9]\d*))?"
            r"(?:-(?P<prerelease>[0-9A-Za-z-.]+))?"
            r"(?:\+(?P<build>[0-9A-Za-z-.]+))?$"
        )

        match = re.match(pattern, version)
        if not match:
            raise ValueError(f"Invalid version: {version}")

        minor = match.group("minor")
        patch = match.group("patch")

        if not optional_minor_and_patch and (minor is None or patch is None):
            raise ValueError(f"Invalid version: {version}")

        return cls(
            major=int(match.group("major")),
            minor=int(minor or 0),
            patch=int(patch or 0),
            prerelease=match.group("prerelease"),
            build=match.group("build"),
        )

    def _cmp_tuple(self):
        prerelease_key = ()
        if self.prerelease is not None:
            prerelease_key = tuple(
                int(part) if part.isdigit() else part for part in self.prerelease.split(".")
            )
        return (self.major, self.minor, self.patch, prerelease_key)

    def __lt__(self, other: "Version") -> bool:  # type: ignore[override]
        return self._cmp_tuple() < other._cmp_tuple()

    def __le__(self, other: "Version") -> bool:  # type: ignore[override]
        return self._cmp_tuple() <= other._cmp_tuple()

    def __gt__(self, other: "Version") -> bool:  # type: ignore[override]
        return self._cmp_tuple() > other._cmp_tuple()

    def __ge__(self, other: "Version") -> bool:  # type: ignore[override]
        return self._cmp_tuple() >= other._cmp_tuple()
