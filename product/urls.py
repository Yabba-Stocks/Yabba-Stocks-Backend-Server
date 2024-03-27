from django.urls import path

from .views import (
    ProductView,
    RetrieveSingleProduct,
    ListAllProducts,
)


urlpatterns = [
    path("create-product/", ProductView.as_view(), name="create_product"),
    path("get-product/<int:id>/", RetrieveSingleProduct.as_view(), name="get_product"),
    path("list-all-products/", ListAllProducts.as_view(), name="list_all_products"),
]
