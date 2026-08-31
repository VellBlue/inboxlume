from __future__ import annotations

import unittest

from scripts.check_desktop_environment import python_version_supported


class DesktopEnvironmentTests(unittest.TestCase):
    def test_supported_python_range_matches_project_metadata(self) -> None:
        self.assertTrue(python_version_supported((3, 11)))
        self.assertTrue(python_version_supported((3, 13)))
        self.assertFalse(python_version_supported((3, 10)))
        self.assertFalse(python_version_supported((3, 14)))


if __name__ == "__main__":
    unittest.main()
