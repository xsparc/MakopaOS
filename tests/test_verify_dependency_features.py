from __future__ import annotations

import unittest

from scripts.verify_dependency_features import feature_violations


class VerifyDependencyFeaturesTests(unittest.TestCase):
    def test_accepts_pinned_instructions_only_edge(self) -> None:
        tree = '''makopa-kernel v0.1.0
└── x86_64 feature "instructions"
    └── x86_64 v0.15.5
'''
        self.assertEqual([], feature_violations(tree))

    def test_rejects_default_or_nightly_features(self) -> None:
        tree = '''x86_64 feature "instructions"
x86_64 feature "default"
x86_64 feature "nightly"
x86_64 feature "abi_x86_interrupt"
x86_64 v0.15.5
'''
        errors = feature_violations(tree)
        self.assertTrue(any("default" in error for error in errors))
        self.assertTrue(any("nightly" in error for error in errors))
        self.assertTrue(any("abi_x86_interrupt" in error for error in errors))

    def test_rejects_wrong_version_or_missing_feature(self) -> None:
        errors = feature_violations("x86_64 v0.15.4\n")
        self.assertTrue(any("instructions" in error for error in errors))
        self.assertTrue(any("0.15.5" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
