from django.apps import AppConfig


class AssessmentsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "assessments"

    def ready(self):
        # Connects the receiver that deletes a stored artifact's file with its row.
        from assessments import artifact_store  # noqa: F401
        # Receivers for `server_started` and `normalization_starting` - see lifecycle.py.
        from assessments import lifecycle  # noqa: F401
