from systems.models import ManagedSystem, ManagedSystemType, SystemScan
from django.contrib import admin


@admin.register(ManagedSystem, ManagedSystemType, SystemScan)
class SystemAdmin(admin.ModelAdmin):
    pass
