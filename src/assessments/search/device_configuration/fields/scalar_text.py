"""The text operator set every configuration compiler advertises.

Each compiler builds its own lookups against its own model; what they share is which
operators a text field offers, so the query builder's dropdown is the same everywhere.
"""

from __future__ import annotations


SUPPORTED_OPERATORS = {"eq", "contains", "is_empty"}
