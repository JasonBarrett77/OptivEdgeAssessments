"""One module per worksheet.

Explicit rather than a namespace package: `setuptools.packages.find` looks for `__init__.py`,
so without this the sheets import fine from a source checkout and are MISSING from the wheel.
"""
