from __future__ import annotations

import hashlib
import math
import statistics
from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable

from .local_models import HardwareProfile, LocalModelProfile, model_spec
from .models import ProviderKind
from .settings import MessageDestination
from .threat_signals import ThreatSemanticMode


class EstimateConfidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class ScanTimingSample:
    processed_messages: int
    elapsed_seconds: float

    def __post_init__(self) -> None:
        if (
            isinstance(self.processed_messages, bool)
            or not isinstance(self.processed_messages, int)
            or self.processed_messages < 1
        ):
            raise ValueError("timing sample must contain processed messages")
        if (
            isinstance(self.elapsed_seconds, bool)
            or not isinstance(self.elapsed_seconds, (int, float))
            or not math.isfinite(float(self.elapsed_seconds))
            or self.elapsed_seconds <= 0
        ):
            raise ValueError("timing sample duration must be positive and finite")

    @property
    def seconds_per_message(self) -> float:
        return self.elapsed_seconds / self.processed_messages


@dataclass(frozen=True, slots=True)
class ScanDurationEstimate:
    eligible_unprocessed: int
    planned_messages: int
    session_limit_reached: bool
    estimated_seconds: float
    lower_seconds: float
    upper_seconds: float
    confidence: EstimateConfidence
    timing_sample_count: int
    basis: str
    factors: tuple[str, ...]
    reads_bodies: bool = False
    loads_model: bool = False
    changes_mailbox: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "type": "scan_duration_estimate",
            "eligible_unprocessed": self.eligible_unprocessed,
            "planned_messages": self.planned_messages,
            "session_limit_reached": self.session_limit_reached,
            "estimated_seconds": round(self.estimated_seconds, 1),
            "lower_seconds": round(self.lower_seconds, 1),
            "upper_seconds": round(self.upper_seconds, 1),
            "confidence": self.confidence.value,
            "timing_sample_count": self.timing_sample_count,
            "basis": self.basis,
            "factors": list(self.factors),
            "read_bodies": self.reads_bodies,
            "loads_model": self.loads_model,
            "changes_mailbox": self.changes_mailbox,
            "stored_plaintext": False,
        }


def hardware_timing_key(
    hardware: HardwareProfile,
    *,
    threat_protection_enabled: bool = True,
    threat_semantic_mode: ThreatSemanticMode = ThreatSemanticMode.TARGETED_SEMANTIC,
    lumegraph_enabled: bool = True,
    obsolescence_proof_enabled: bool = True,
) -> str:
    memory_bucket = (
        "unknown"
        if hardware.total_memory_gib is None
        else str(int(round(hardware.total_memory_gib / 4.0) * 4))
    )
    material = (
        "scan-pipeline-v5-targeted-threat-screening\0"
        f"{hardware.system_name.casefold()}\0"
        f"{hardware.machine.casefold()}\0{memory_bucket}\0"
        f"threat={int(threat_protection_enabled)}\0"
        f"threat-mode={threat_semantic_mode.value}\0"
        f"lumegraph={int(lumegraph_enabled)}\0"
        f"proof={int(obsolescence_proof_enabled)}"
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _chunked_reference_seconds(
    messages: int,
    chunk_size: int,
    seconds_per_message: float,
    cold_floor: float,
) -> float:
    if messages == 0:
        return 0.0
    remaining = messages
    total = 0.0
    while remaining:
        chunk = min(remaining, chunk_size)
        total += max(cold_floor, chunk * seconds_per_message)
        remaining -= chunk
    return total


def estimate_scan_duration(
    *,
    eligible_unprocessed: int,
    session_limit_reached: bool,
    model_profile: LocalModelProfile,
    hardware: HardwareProfile,
    provider: ProviderKind,
    destination: MessageDestination,
    governor_enforced: bool,
    action_fraction: float,
    lifecycle_fraction: float = 0.30,
    threat_protection_enabled: bool = True,
    threat_semantic_mode: ThreatSemanticMode = ThreatSemanticMode.TARGETED_SEMANTIC,
    threat_semantic_fraction: float = 0.20,
    lumegraph_enabled: bool = True,
    obsolescence_proof_enabled: bool = True,
    timing_samples: Iterable[ScanTimingSample] = (),
) -> ScanDurationEstimate:
    if (
        isinstance(eligible_unprocessed, bool)
        or not isinstance(eligible_unprocessed, int)
        or eligible_unprocessed < 0
    ):
        raise ValueError("eligible count cannot be negative")
    if (
        isinstance(action_fraction, bool)
        or not isinstance(action_fraction, (int, float))
        or not math.isfinite(float(action_fraction))
        or not 0.0 <= float(action_fraction) <= 1.0
    ):
        raise ValueError("action fraction must be between zero and one")
    if (
        isinstance(lifecycle_fraction, bool)
        or not isinstance(lifecycle_fraction, (int, float))
        or not math.isfinite(float(lifecycle_fraction))
        or not 0.0 <= float(lifecycle_fraction) <= 1.0
    ):
        raise ValueError("lifecycle fraction must be between zero and one")
    if (
        isinstance(threat_semantic_fraction, bool)
        or not isinstance(threat_semantic_fraction, (int, float))
        or not math.isfinite(float(threat_semantic_fraction))
        or not 0.0 <= float(threat_semantic_fraction) <= 1.0
    ):
        raise ValueError("threat semantic fraction must be between zero and one")
    samples = tuple(timing_samples)
    planned = eligible_unprocessed
    factors = [model_profile.value, provider.value, destination.value]
    if threat_protection_enabled:
        factors.append("local_threat_technical")
        if threat_semantic_mode is ThreatSemanticMode.TARGETED_SEMANTIC:
            factors.append("targeted_local_threat_semantics")
    if lumegraph_enabled:
        factors.append("lumegraph_shadow")
    if obsolescence_proof_enabled:
        factors.append("proof_of_obsolescence")
    if governor_enforced:
        factors.append("safety_governor")
    if session_limit_reached:
        factors.append("session_limit")

    if planned == 0:
        return ScanDurationEstimate(
            eligible_unprocessed=0,
            planned_messages=0,
            session_limit_reached=session_limit_reached,
            estimated_seconds=0.0,
            lower_seconds=0.0,
            upper_seconds=0.0,
            confidence=EstimateConfidence.HIGH,
            timing_sample_count=len(samples),
            basis="no_eligible_messages",
            factors=tuple(factors),
        )

    spec = model_spec(model_profile)
    if samples:
        rates = sorted(sample.seconds_per_message for sample in samples)
        central_rate = statistics.median(rates)
        central = max(spec.observed_cold_seconds, central_rate * planned)
        lower = max(spec.observed_cold_seconds * 0.75, min(rates) * planned * 0.8)
        upper = max(spec.observed_cold_seconds * 1.25, max(rates) * planned * 1.25)
        spread = max(rates) / min(rates) if min(rates) > 0 else math.inf
        confidence = (
            EstimateConfidence.HIGH
            if len(samples) >= 3 and spread <= 1.5
            else EstimateConfidence.MEDIUM
        )
        basis = "matching_local_sessions"
        factors.append(f"local_samples:{len(samples)}")
    else:
        base_rate = spec.observed_cold_seconds / 5.0
        lower_rate = base_rate * 0.70
        upper_rate = base_rate * (
            2.20 if model_profile is LocalModelProfile.GEMMA12 else 1.80
        )
        memory_factor = 1.0
        upper_memory_factor = 1.0
        if hardware.total_memory_gib is None:
            upper_memory_factor = 1.35
            factors.append("memory_unknown")
        elif hardware.total_memory_gib < spec.recommended_memory_gib:
            memory_factor = 1.25
            upper_memory_factor = 1.55
            factors.append("memory_below_recommended")
        if not hardware.apple_silicon:
            # The published reference observations came from Apple Silicon.
            upper_memory_factor *= 1.25
            factors.append("different_reference_hardware")
        central = _chunked_reference_seconds(
            planned,
            500,
            base_rate * memory_factor,
            spec.observed_cold_seconds * memory_factor,
        )
        lower = _chunked_reference_seconds(
            planned,
            500,
            lower_rate,
            spec.observed_cold_seconds * 0.70,
        )
        upper = _chunked_reference_seconds(
            planned,
            500,
            upper_rate * upper_memory_factor,
            spec.observed_cold_seconds * 1.40 * upper_memory_factor,
        )
        confidence = EstimateConfidence.LOW
        basis = "preliminary_reference_benchmark"

        # Technical screening is lightweight.  In targeted mode the local model
        # sees only messages that already have a technical warning, never every
        # message.  Matching local samples already measure the full pipeline.
        semantic_factor = (
            0.85 * threat_semantic_fraction
            if (
                threat_protection_enabled
                and threat_semantic_mode is ThreatSemanticMode.TARGETED_SEMANTIC
            )
            else 0.0
        )
        lifecycle_factor = 0.65 * lifecycle_fraction if lumegraph_enabled else 0.0
        proof_factor = 0.05 if obsolescence_proof_enabled else 0.0
        central *= 1.0 + semantic_factor + lifecycle_factor + proof_factor
        lower *= 1.0 + (
            0.65 * threat_semantic_fraction
            if (
                threat_protection_enabled
                and threat_semantic_mode is ThreatSemanticMode.TARGETED_SEMANTIC
            )
            else 0.0
        ) + (
            0.45 * lifecycle_fraction if lumegraph_enabled else 0.0
        ) + (0.03 if obsolescence_proof_enabled else 0.0)
        upper *= 1.0 + (
            1.10 * threat_semantic_fraction
            if (
                threat_protection_enabled
                and threat_semantic_mode is ThreatSemanticMode.TARGETED_SEMANTIC
            )
            else 0.0
        ) + (
            0.90 * lifecycle_fraction if lumegraph_enabled else 0.0
        ) + (0.08 if obsolescence_proof_enabled else 0.0)

    if not samples:
        # Reference benchmarks cover model work only. Provider retrieval and
        # optional mutations are therefore added here. Matching local samples
        # already measure the complete end-to-end session and must not be
        # charged a second time.
        network_per_message = 0.10 if provider is ProviderKind.GMAIL else 0.18
        mutation_per_action = 0.18 if provider is ProviderKind.GMAIL else 0.28
        destination_factor = 1.08 if destination is MessageDestination.TRASH else 1.0
        overhead = planned * network_per_message
        overhead += planned * action_fraction * mutation_per_action * destination_factor
        if governor_enforced:
            overhead += min(2.0, 0.005 * planned)
        if obsolescence_proof_enabled:
            overhead += min(1.5, 0.003 * planned)
        central += overhead
        lower += overhead * 0.60
        upper += overhead * 1.80

    central = max(0.0, central)
    lower = max(0.0, min(lower, central))
    upper = max(central, upper)
    return ScanDurationEstimate(
        eligible_unprocessed=eligible_unprocessed,
        planned_messages=planned,
        session_limit_reached=session_limit_reached,
        estimated_seconds=central,
        lower_seconds=lower,
        upper_seconds=upper,
        confidence=confidence,
        timing_sample_count=len(samples),
        basis=basis,
        factors=tuple(factors),
    )
