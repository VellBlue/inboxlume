from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Callable, Mapping, Sequence


class LocalModelProfile(StrEnum):
    QWEN8 = "qwen8"
    GEMMA12 = "gemma12"
    GEMMA26 = "gemma26"


@dataclass(frozen=True, slots=True)
class LocalModelSpec:
    profile: LocalModelProfile
    display_name: str
    tier: str
    backend: str
    ollama_model: str
    recommended_memory_gib: int
    observed_cold_seconds: float
    observed_peak_gib: float | None
    review_confidence: float
    quarantine_confidence: float
    direct_trash_allowed: bool
    quality_notice: str
    mlx_cache_directory: str | None = None


MODEL_CATALOG: dict[LocalModelProfile, LocalModelSpec] = {
    LocalModelProfile.QWEN8: LocalModelSpec(
        LocalModelProfile.QWEN8,
        "Qwen 8B · Lightweight",
        "Lightweight",
        "ollama",
        "qwen3-vl:8b",
        12,
        5.4,
        None,
        0.80,
        0.90,
        False,
        "The lightest profile, but preliminary tests showed more confusion between "
        "legitimate advertising and spam. It uses stricter thresholds and Quarantine only.",
    ),
    LocalModelProfile.GEMMA12: LocalModelSpec(
        LocalModelProfile.GEMMA12,
        "Gemma 12B · Balanced",
        "Balanced",
        "gemma12",
        "qwen3-vl:8b",
        16,
        8.7,
        11.2,
        0.75,
        0.85,
        False,
        "A balanced profile, currently available through MLX on Apple Silicon Macs. "
        "For now, it uses Quarantine only.",
        "models--mlx-community--gemma-4-12B-it-qat-4bit",
    ),
    LocalModelProfile.GEMMA26: LocalModelSpec(
        LocalModelProfile.GEMMA26,
        "Gemma 26B-A4B · Recommended",
        "Recommended",
        "gemma26",
        "qwen3-vl:8b",
        24,
        9.7,
        14.7,
        0.70,
        0.80,
        True,
        "Provisionally recommended by the local benchmarks: higher observed quality, "
        "with greater memory use.",
        "models--mlx-community--gemma-4-26B-A4B-it-heretic-4bit",
    ),
}

SHADOW_POLICY_VERSION = "policy-v2"


@dataclass(frozen=True, slots=True)
class HardwareProfile:
    system_name: str
    machine: str
    total_memory_gib: float | None

    @property
    def apple_silicon(self) -> bool:
        return self.system_name == "Darwin" and self.machine.casefold() in {
            "arm64",
            "aarch64",
        }


@dataclass(frozen=True, slots=True)
class ModelAvailability:
    profile: LocalModelProfile
    available: bool
    detail: str
    memory_warning: bool = False


def model_spec(profile: LocalModelProfile | str) -> LocalModelSpec:
    return MODEL_CATALOG[LocalModelProfile(profile)]


def scan_profile_for_model(profile: LocalModelProfile | str) -> str:
    """Return the stable ledger profile used by scans and local safety evidence."""
    spec = model_spec(profile)
    model_key = (
        spec.ollama_model.replace(":", "-")
        if spec.backend == "ollama"
        else spec.backend
    )
    return f"{model_key}-{SHADOW_POLICY_VERSION}"


def profile_for_backend(
    backend: str,
    ollama_model: str = "qwen3-vl:8b",
) -> LocalModelProfile | None:
    if backend == "ollama":
        if ollama_model != MODEL_CATALOG[LocalModelProfile.QWEN8].ollama_model:
            raise ValueError("Ollama model is not allowed by the InboxLume profile")
        return LocalModelProfile.QWEN8
    if backend in {LocalModelProfile.GEMMA12.value, LocalModelProfile.GEMMA26.value}:
        return LocalModelProfile(backend)
    if backend == "heuristic":
        return None
    raise ValueError("local backend is not allowed")


def _total_memory_bytes(system_name: str) -> int | None:
    if system_name == "Windows":
        try:
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = (
                    ("length", ctypes.c_ulong),
                    ("memory_load", ctypes.c_ulong),
                    ("total_physical", ctypes.c_ulonglong),
                    ("available_physical", ctypes.c_ulonglong),
                    ("total_page_file", ctypes.c_ulonglong),
                    ("available_page_file", ctypes.c_ulonglong),
                    ("total_virtual", ctypes.c_ulonglong),
                    ("available_virtual", ctypes.c_ulonglong),
                    ("available_extended_virtual", ctypes.c_ulonglong),
                )

            status = MemoryStatus()
            status.length = ctypes.sizeof(MemoryStatus)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.total_physical)
        except (AttributeError, OSError, TypeError, ValueError):
            return None
        return None
    try:
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        page_count = int(os.sysconf("SC_PHYS_PAGES"))
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    return page_size * page_count if page_size > 0 and page_count > 0 else None


def detect_hardware(
    *,
    system_name: str | None = None,
    machine: str | None = None,
    total_memory_bytes: int | None = None,
) -> HardwareProfile:
    selected_system = system_name or platform.system()
    selected_machine = machine or platform.machine()
    memory = (
        total_memory_bytes
        if total_memory_bytes is not None
        else _total_memory_bytes(selected_system)
    )
    memory_gib = round(memory / (1024**3), 1) if memory is not None else None
    return HardwareProfile(selected_system, selected_machine, memory_gib)


def resolve_cached_gemma(
    profile: LocalModelProfile | str,
    *,
    home: Path | None = None,
) -> Path:
    spec = model_spec(profile)
    if spec.mlx_cache_directory is None:
        raise ValueError("this profile does not use a Gemma MLX cache")
    user_home = home or Path.home()
    model_root = user_home / ".cache" / "huggingface" / "hub" / spec.mlx_cache_directory
    snapshots = sorted(
        path.parent for path in (model_root / "snapshots").glob("*/config.json")
    )
    if len(snapshots) != 1:
        raise RuntimeError(f"local {spec.profile.value} cache is missing or ambiguous")
    snapshot = snapshots[0].resolve()
    if model_root.resolve() not in snapshot.parents:
        raise RuntimeError("invalid Gemma cache path")
    return snapshot


def resolve_mlx_python(*, home: Path | None = None) -> Path:
    user_home = home or Path.home()
    candidates = (
        user_home / ".local" / "share" / "uv" / "tools" / "mlx-lm" / "bin" / "python",
        Path(sys.executable),
    )
    for candidate in candidates:
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        if candidate == Path(sys.executable):
            try:
                import mlx_lm  # noqa: F401
            except ModuleNotFoundError:
                continue
        # Keep the uv tool's symlink intact.  Resolving it points at uv's
        # standalone base interpreter and drops the tool environment from
        # ``sys.path``, making the installed ``mlx_lm`` package invisible.
        return candidate
    raise RuntimeError("local MLX runtime unavailable")


def _ollama_executable(
    *,
    system_name: str,
    home: Path,
    environ: Mapping[str, str],
) -> Path | None:
    discovered = shutil.which("ollama", path=environ.get("PATH"))
    candidates: list[Path] = [Path(discovered)] if discovered else []
    if system_name == "Darwin":
        candidates.extend((Path("/opt/homebrew/bin/ollama"), Path("/usr/local/bin/ollama")))
    elif system_name == "Windows":
        local_app_data = environ.get("LOCALAPPDATA", "").strip()
        if local_app_data:
            candidates.append(Path(local_app_data) / "Programs" / "Ollama" / "ollama.exe")
    else:
        candidates.extend((Path("/usr/local/bin/ollama"), Path("/usr/bin/ollama")))
    candidates.append(home / ".local" / "bin" / "ollama")
    return next(
        (
            candidate.resolve()
            for candidate in candidates
            if candidate.is_file() and os.access(candidate, os.X_OK)
        ),
        None,
    )


def _ollama_manifest_exists(home: Path, model: str) -> bool:
    family, tag = model.split(":", 1)
    manifest = (
        home
        / ".ollama"
        / "models"
        / "manifests"
        / "registry.ollama.ai"
        / "library"
        / family
        / tag
    )
    return manifest.is_file()


def _runtime_probe(
    executable: Path,
    arguments: Sequence[str],
    environment: Mapping[str, str],
) -> bool:
    offline_environment = dict(environment)
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        offline_environment.pop(name, None)
    offline_environment.update(
        {
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "NO_PROXY": "*",
            "no_proxy": "*",
        }
    )
    try:
        completed = subprocess.run(
            [str(executable), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
            env=offline_environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def inspect_model_availability(
    hardware: HardwareProfile,
    *,
    home: Path | None = None,
    environ: Mapping[str, str] | None = None,
    command_probe: Callable[[Path, Sequence[str], Mapping[str, str]], bool]
    | None = None,
) -> dict[LocalModelProfile, ModelAvailability]:
    user_home = home or Path.home()
    environment = os.environ if environ is None else environ
    probe = command_probe or _runtime_probe
    results: dict[LocalModelProfile, ModelAvailability] = {}
    for profile, spec in MODEL_CATALOG.items():
        memory_warning = (
            hardware.total_memory_gib is not None
            and hardware.total_memory_gib < spec.recommended_memory_gib
        )
        if profile is LocalModelProfile.QWEN8:
            runtime = _ollama_executable(
                system_name=hardware.system_name,
                home=user_home,
                environ=environment,
            )
            cached = _ollama_manifest_exists(user_home, spec.ollama_model)
            runtime_ready = bool(
                runtime is not None
                and cached
                and probe(runtime, ("show", spec.ollama_model), environment)
            )
            if runtime is None:
                detail = "Ollama is not installed or could not be detected"
            elif not cached:
                detail = f"Local model {spec.ollama_model} is not available"
            elif not runtime_ready:
                detail = "Ollama runtime did not pass the local readiness check"
            else:
                detail = "Ready through local Ollama; the model is unloaded from RAM after the batch"
            results[profile] = ModelAvailability(
                profile,
                runtime_ready,
                detail,
                memory_warning,
            )
            continue
        if not hardware.apple_silicon:
            results[profile] = ModelAvailability(
                profile,
                False,
                "MLX currently requires macOS on Apple Silicon",
                memory_warning,
            )
            continue
        try:
            mlx_python = resolve_mlx_python(home=user_home)
            resolve_cached_gemma(profile, home=user_home)
        except (OSError, RuntimeError, ValueError) as exc:
            results[profile] = ModelAvailability(profile, False, str(exc), memory_warning)
        else:
            if not probe(
                mlx_python,
                ("-c", "import mlx.core; import mlx_lm"),
                environment,
            ):
                results[profile] = ModelAvailability(
                    profile,
                    False,
                    "MLX runtime did not pass the local import check",
                    memory_warning,
                )
                continue
            detail = "Ready from the local Hugging Face cache with networking disabled"
            if memory_warning:
                detail += f"; at least {spec.recommended_memory_gib} GB RAM is recommended"
            results[profile] = ModelAvailability(profile, True, detail, memory_warning)
    return results


def recommended_available_profile(
    availability: Mapping[LocalModelProfile, ModelAvailability],
) -> LocalModelProfile | None:
    for profile in (
        LocalModelProfile.GEMMA26,
        LocalModelProfile.GEMMA12,
        LocalModelProfile.QWEN8,
    ):
        status = availability.get(profile)
        if status is not None and status.available and not status.memory_warning:
            return profile
    for profile in (
        LocalModelProfile.GEMMA26,
        LocalModelProfile.GEMMA12,
        LocalModelProfile.QWEN8,
    ):
        status = availability.get(profile)
        if status is not None and status.available:
            return profile
    return None
