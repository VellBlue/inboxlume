from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from unittest.mock import patch

from inboxlume.local_models import (
    LocalModelProfile,
    _process_is_translated,
    detect_hardware,
    inspect_model_availability,
    model_spec,
    profile_for_backend,
    recommended_available_profile,
    resolve_cached_gemma,
    resolve_mlx_python,
    scan_profile_for_model,
)


class LocalModelTests(unittest.TestCase):
    def _gemma_cache(self, home: Path, profile: LocalModelProfile) -> None:
        cache = model_spec(profile).mlx_cache_directory
        assert cache is not None
        snapshot = home / ".cache/huggingface/hub" / cache / "snapshots/test"
        snapshot.mkdir(parents=True)
        (snapshot / "config.json").write_text("{}")

    def test_catalog_keeps_smaller_model_quality_warning_explicit(self) -> None:
        qwen = model_spec(LocalModelProfile.QWEN8)
        gemma = model_spec(LocalModelProfile.GEMMA26)
        self.assertIn("confusion", qwen.quality_notice)
        self.assertEqual(gemma.tier, "Recommended")
        self.assertGreater(gemma.recommended_memory_gib, qwen.recommended_memory_gib)
        self.assertFalse(qwen.direct_trash_allowed)
        self.assertTrue(gemma.direct_trash_allowed)
        self.assertGreater(qwen.quarantine_confidence, gemma.quarantine_confidence)

    def test_backends_map_only_to_controlled_profiles(self) -> None:
        self.assertEqual(
            profile_for_backend("ollama", "qwen3-vl:8b"),
            LocalModelProfile.QWEN8,
        )
        self.assertEqual(
            profile_for_backend("gemma12"),
            LocalModelProfile.GEMMA12,
        )
        with self.assertRaises(ValueError):
            profile_for_backend("ollama", "untrusted:latest")
        self.assertEqual(
            scan_profile_for_model(LocalModelProfile.QWEN8),
            "qwen3-vl-8b-policy-v2",
        )
        self.assertEqual(
            scan_profile_for_model(LocalModelProfile.GEMMA26),
            "gemma26-policy-v2",
        )

    def test_apple_silicon_detects_only_cached_allowlisted_gemma(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            self._gemma_cache(home, LocalModelProfile.GEMMA26)
            mlx_python = home / ".local/share/uv/tools/mlx-lm/bin/python"
            mlx_python.parent.mkdir(parents=True)
            mlx_python.write_text("")
            mlx_python.chmod(0o755)
            hardware = detect_hardware(
                system_name="Darwin",
                machine="arm64",
                total_memory_bytes=32 * 1024**3,
            )

            status = inspect_model_availability(
                hardware,
                home=home,
                environ={"PATH": ""},
                command_probe=lambda *_: True,
            )

            self.assertTrue(status[LocalModelProfile.GEMMA26].available)
            self.assertFalse(status[LocalModelProfile.GEMMA12].available)
            self.assertEqual(
                recommended_available_profile(status),
                LocalModelProfile.GEMMA26,
            )

    def test_non_apple_platform_rejects_mlx_but_accepts_cached_ollama(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            executable = home / ".local/bin/ollama"
            executable.parent.mkdir(parents=True)
            executable.write_text("")
            executable.chmod(0o755)
            manifest = home / (
                ".ollama/models/manifests/registry.ollama.ai/library/qwen3-vl/8b"
            )
            manifest.parent.mkdir(parents=True)
            manifest.write_text("{}")
            hardware = detect_hardware(
                system_name="Linux",
                machine="x86_64",
                total_memory_bytes=16 * 1024**3,
            )

            status = inspect_model_availability(
                hardware,
                home=home,
                environ={"PATH": ""},
                command_probe=lambda *_: True,
            )

            self.assertTrue(status[LocalModelProfile.QWEN8].available)
            self.assertFalse(status[LocalModelProfile.GEMMA12].available)
            self.assertFalse(status[LocalModelProfile.GEMMA26].available)
            self.assertEqual(
                recommended_available_profile(status),
                LocalModelProfile.QWEN8,
            )

    def test_ambiguous_gemma_cache_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            cache = model_spec(LocalModelProfile.GEMMA12).mlx_cache_directory
            assert cache is not None
            for name in ("one", "two"):
                snapshot = home / ".cache/huggingface/hub" / cache / "snapshots" / name
                snapshot.mkdir(parents=True)
                (snapshot / "config.json").write_text("{}")
            with self.assertRaisesRegex(RuntimeError, "missing or ambiguous"):
                resolve_cached_gemma(LocalModelProfile.GEMMA12, home=home)

    def test_mlx_runtime_keeps_uv_environment_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            target = home / "uv-python" / "bin" / "python3.12"
            target.parent.mkdir(parents=True)
            target.write_text("")
            target.chmod(0o755)
            candidate = home / ".local/share/uv/tools/mlx-lm/bin/python"
            candidate.parent.mkdir(parents=True)
            candidate.symlink_to(target)

            self.assertEqual(resolve_mlx_python(home=home), candidate)

    def test_file_presence_alone_does_not_report_mlx_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            self._gemma_cache(home, LocalModelProfile.GEMMA26)
            mlx_python = home / ".local/share/uv/tools/mlx-lm/bin/python"
            mlx_python.parent.mkdir(parents=True)
            mlx_python.write_text("")
            mlx_python.chmod(0o755)
            hardware = detect_hardware(
                system_name="Darwin",
                machine="arm64",
                total_memory_bytes=32 * 1024**3,
            )

            status = inspect_model_availability(
                hardware, home=home, environ={"PATH": ""}
            )

        self.assertFalse(status[LocalModelProfile.GEMMA26].available)
        self.assertIn("import check", status[LocalModelProfile.GEMMA26].detail)


class RosettaTranslationTests(unittest.TestCase):
    """A translated process sees x86_64 on hardware that fully supports MLX."""

    ROOT = Path(__file__).resolve().parents[1]

    def test_a_translated_mac_is_not_reported_as_unsupported_hardware(self) -> None:
        hardware = detect_hardware(
            system_name="Darwin",
            machine="x86_64",
            total_memory_bytes=24 * 1024**3,
            translated=True,
        )
        detail = inspect_model_availability(hardware)[LocalModelProfile.GEMMA26].detail

        self.assertTrue(hardware.translated)
        self.assertIn("Rosetta", detail)
        self.assertNotIn("requires macOS on Apple Silicon", detail)

    def test_genuinely_unsupported_hardware_still_says_so(self) -> None:
        hardware = detect_hardware(
            system_name="Linux",
            machine="x86_64",
            total_memory_bytes=24 * 1024**3,
            translated=False,
        )
        detail = inspect_model_availability(hardware)[LocalModelProfile.GEMMA26].detail

        self.assertIn("Apple Silicon", detail)
        self.assertNotIn("Rosetta", detail)

    def test_translation_is_only_ever_asked_of_macos(self) -> None:
        with patch("inboxlume.local_models.subprocess.run") as run:
            self.assertFalse(_process_is_translated("Linux"))
            self.assertFalse(_process_is_translated("Windows"))
        run.assert_not_called()

    def test_a_failed_probe_never_claims_translation(self) -> None:
        with patch(
            "inboxlume.local_models.subprocess.run",
            side_effect=OSError("sysctl assente"),
        ):
            self.assertFalse(_process_is_translated("Darwin"))

    def test_the_macos_bundle_refuses_translation_up_front(self) -> None:
        plist = (self.ROOT / "macos/InboxLume-Info.plist").read_text(encoding="utf-8")

        # The launcher guard repairs a translated start; this prevents it, and
        # covers opening the app from the Dock or the Finder.
        self.assertIn("LSRequiresNativeExecution", plist)
        self.assertIn("LSArchitecturePriority", plist)
        priority = plist.index("LSArchitecturePriority")
        self.assertLess(plist.index("arm64", priority), plist.index("x86_64", priority))

    def test_both_launchers_restart_natively_before_doing_anything(self) -> None:
        for name in ("macos/InboxLumeLauncher.sh", "Avvia InboxLume.command"):
            with self.subTest(launcher=name):
                script = (self.ROOT / name).read_text(encoding="utf-8")
                self.assertIn("sysctl.proc_translated", script)
                self.assertIn("/usr/bin/arch -arm64", script)
                # The marker keeps a stubborn environment from looping.
                self.assertIn("INBOXLUME_NATIVE_REEXEC", script)
                guard = script.index("sysctl.proc_translated")
                self.assertLess(guard, len(script) // 2)


if __name__ == "__main__":
    unittest.main()
