from django.apps import AppConfig

class CloudstorageConfig(AppConfig):
    name = 'cloudstorage'

    def ready(self):
        from . import signals  # noqa: F401
