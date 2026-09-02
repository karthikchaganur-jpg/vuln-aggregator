from rest_framework.routers import DefaultRouter

from .views import AssetViewSet, FindingViewSet

router = DefaultRouter()
router.register("assets", AssetViewSet)
router.register("findings", FindingViewSet)

urlpatterns = router.urls
