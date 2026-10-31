"""A test that never runs reports as a pass, so this is the one thing the suite cannot self-check.

Found by the av-wildfire stage 8 run, 2026-10-31: four methods in
`test_policy_hygiene_controls.py` had never executed, because three names were each defined twice
in one `TestCase` class - once thrice - and Python binds the last. Two of them were PAN-AVW-003's,
and one was asserting the very scope clause that run removed. **So the clause survived a ruling
that had removed it everywhere else, because the only thing guarding it was a test that did not
run.**

THIS IS A GATE RATHER THAN A SWEEP ON PURPOSE. The sweep first written for it,
`grep -o 'def test_[a-z_0-9]*' <file> | sort | uniq -d`, does not respect class boundaries, so it
reports two same-named methods in two DIFFERENT classes - which is legal, ordinary, and present in
`test_authentication_profile_controls.py`, where `AllowListScopingTests` and its neighbour each
test a device-wide binding for a different control. A sweep with a false-positive mode costs every
later run the time to rule it out; a gate costs nobody anything until it fires.
"""

import ast
import collections
from pathlib import Path

from django.test import SimpleTestCase

TESTS_DIR = Path(__file__).resolve().parent


class NoTestMethodShadowsAnother(SimpleTestCase):
    def test_no_test_class_defines_one_test_name_twice(self):
        """Read with `ast` rather than by import: a module that fails to import would otherwise
        take its shadowed methods with it, and this must hold for every file on disk."""
        shadowed = {}
        for path in sorted(TESTS_DIR.glob("test_*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not isinstance(node, ast.ClassDef):
                    continue
                counts = collections.Counter(
                    body.name for body in node.body
                    if isinstance(body, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and body.name.startswith("test"))
                for name, seen in sorted(counts.items()):
                    if seen > 1:
                        shadowed[f"{path.name}::{node.name}::{name}"] = seen
        self.assertEqual(
            shadowed, {},
            "each of these test names is defined more than once in one class, so only the last "
            "definition runs and the earlier ones have never executed")
