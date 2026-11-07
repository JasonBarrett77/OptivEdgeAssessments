"""The default settings, with a test database that survives the run.

WHAT THIS IS FOR. Under `settings.default` the test database is sqlite's `:memory:`, which
cannot outlive the process, so every run rebuilds the schema from the migrations before it
runs a single test - 64 migrations, about two minutes, measured 2026-11-07. A one-module run
that takes 19 seconds therefore costs two and a half minutes, and almost all of it is spent
proving again what the last run already proved.

Naming the test database gives `--keepdb` something to keep:

    DJANGO_SETTINGS_MODULE=assessments.settings.fast PYTHONPATH=./src \\
        .venv/bin/python -m django test --keepdb assessments.tests.test_health_check

The FIRST run with this pays the two minutes and leaves the database behind; every run after
it starts in a second or two. `--keepdb` still applies any migration the database has not
seen, so adding one does not mean dropping it - and `test-db.sqlite3` is covered by the
`*.sqlite*` rule in `.gitignore`, so it is never committed.

WHEN NOT TO USE IT. The full suite before a commit runs under `settings.default`, from
nothing, because that is the run that proves the migrations build the schema the tests expect.
A kept database is a database the last run's schema changes are already in; this is the
iteration loop, not the gate.
"""

from .default import *  # noqa: F401,F403
from .default import BASE_DIR, DATABASES

DATABASES["default"]["TEST"] = {"NAME": BASE_DIR / "test-db.sqlite3"}
