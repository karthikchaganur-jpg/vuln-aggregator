from django.contrib import admin

from .models import Asset, Finding


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ["name", "asset_type", "identifier", "criticality"]
    list_filter = ["asset_type"]


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ["title", "asset", "severity", "cvss_score", "status", "sources", "priority_score"]
    list_filter = ["severity", "status"]
    search_fields = ["title", "cve_id", "description"]
