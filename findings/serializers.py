from rest_framework import serializers

from .models import Asset, Finding


class AssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        fields = ["id", "name", "asset_type", "identifier", "criticality"]


class FindingSerializer(serializers.ModelSerializer):
    asset = AssetSerializer(read_only=True)
    asset_id = serializers.PrimaryKeyRelatedField(
        queryset=Asset.objects.all(), source="asset", write_only=True
    )
    priority_score = serializers.ReadOnlyField()

    class Meta:
        model = Finding
        fields = [
            "id",
            "asset",
            "asset_id",
            "cve_id",
            "title",
            "description",
            "severity",
            "cvss_score",
            "status",
            "sources",
            "priority_score",
            "first_seen",
            "last_seen",
        ]
        read_only_fields = ["first_seen", "last_seen", "sources"]
