import django_filters

from .models import Finding


class FindingFilter(django_filters.FilterSet):
    min_cvss = django_filters.NumberFilter(field_name="cvss_score", lookup_expr="gte")
    max_cvss = django_filters.NumberFilter(field_name="cvss_score", lookup_expr="lte")
    source = django_filters.CharFilter(field_name="sources", lookup_expr="icontains")

    class Meta:
        model = Finding
        fields = ["severity", "status", "asset", "min_cvss", "max_cvss", "source"]
