"""Plugin registry: checks announce themselves with the @check decorator."""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable

from .host import Host
from .models import CheckMeta, CheckResult

CheckFn = Callable[[Host], CheckResult]

REGISTRY: dict[str, tuple[CheckMeta, CheckFn]] = {}


def check(meta: CheckMeta):
    """Register a check function under its metadata."""

    def deco(fn: CheckFn) -> CheckFn:
        if meta.id in REGISTRY:
            raise ValueError(f"duplicate check id {meta.id}")
        REGISTRY[meta.id] = (meta, fn)
        return fn

    return deco


def load_all() -> dict[str, tuple[CheckMeta, CheckFn]]:
    """Import every module under ``checks/`` so its decorators run."""
    from . import checks

    for mod in pkgutil.iter_modules(checks.__path__):
        if not mod.name.startswith("_"):
            importlib.import_module(f"{checks.__name__}.{mod.name}")
    return REGISTRY


def all_meta() -> list[CheckMeta]:
    load_all()
    return sorted((meta for meta, _ in REGISTRY.values()), key=lambda m: m.id)


def get(check_id: str) -> tuple[CheckMeta, CheckFn] | None:
    load_all()
    return REGISTRY.get(check_id)


def categories() -> list[str]:
    return sorted({m.category for m in all_meta()})
