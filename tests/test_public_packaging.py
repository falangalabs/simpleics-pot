from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from repository_safety_check import check_repository  # noqa: E402
from simpleics_pot import __version__  # noqa: E402
from simpleics_pot.register_map import PACKAGE_REGISTER_MAP, RegisterMap  # noqa: E402


class PublicPackagingTests(unittest.TestCase):
    def test_runtime_and_release_versions_match(self) -> None:
        self.assertEqual("0.1.0", __version__)

    def test_packaged_register_map_exists_and_loads(self) -> None:
        self.assertTrue(PACKAGE_REGISTER_MAP.is_file())
        loaded = RegisterMap.load(PACKAGE_REGISTER_MAP)
        self.assertEqual(21, len(loaded.definitions))
        self.assertTrue(loaded.document["device"]["synthetic_identity"])

    def test_public_build_manifest_matches_release_version(self) -> None:
        document = json.loads((ROOT / "PUBLIC_BUILD_MANIFEST.json").read_text(encoding="utf-8"))
        self.assertEqual("1.0.0", document["schema_version"])
        self.assertEqual("0.1.0", document["release_version"])
        paths = {item["path"] for item in document["files"]}
        self.assertIn("src/simpleics_pot/runtime.py", paths)
        self.assertNotIn("PUBLIC_BUILD_MANIFEST.json", paths)

    def test_every_manifest_digest_and_size_matches(self) -> None:
        manifest = json.loads(
            (ROOT / "PUBLIC_BUILD_MANIFEST.json").read_text(encoding="utf-8")
        )
        expected_paths = set()
        for entry in manifest["files"]:
            path = ROOT / entry["path"]
            self.assertTrue(path.is_file())
            self.assertFalse(path.is_symlink())
            self.assertEqual(entry["size"], path.stat().st_size)
            self.assertEqual(entry["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            expected_paths.add(entry["path"])

        actual_paths = {
            path.relative_to(ROOT).as_posix()
            for path in ROOT.rglob("*")
            if path.is_file()
            and not any(
                part in {".git", ".venv", "__pycache__", "build", "dist"}
                or part.endswith(".egg-info")
                for part in path.relative_to(ROOT).parts
            )
            and path.suffix != ".pyc"
            and path.name != "PUBLIC_BUILD_MANIFEST.json"
        }
        self.assertEqual(expected_paths, actual_paths)

    def test_repository_safety_check_passes(self) -> None:
        self.assertEqual([], check_repository(ROOT))

    def test_repository_safety_rejects_mutable_action_reference(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / ".github" / "workflows" / "unsafe.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                "steps:\n  - uses: actions/checkout@v7\n",
                encoding="utf-8",
            )
            self.assertTrue(
                any("not pinned" in error for error in check_repository(root))
            )

    def test_repository_safety_rejects_persistent_checkout_credentials(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / ".github" / "workflows" / "unsafe.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                "permissions:\n  contents: read\nsteps:\n"
                "  - uses: actions/checkout@" + "a" * 40 + "\n",
                encoding="utf-8",
            )
            self.assertTrue(
                any("checkout credentials persist" in error for error in check_repository(root))
            )

    def test_repository_safety_rejects_new_package_manager_surface(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "package.json").write_text("{}\n", encoding="utf-8")
            self.assertTrue(
                any("package-manager surface" in error for error in check_repository(root))
            )


if __name__ == "__main__":
    unittest.main()
