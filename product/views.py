from threading import Thread
from concurrent.futures import ThreadPoolExecutor

# Third party imports.
from rest_framework import generics
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.parsers import MultiPartParser, JSONParser
from rest_framework_simplejwt.authentication import JWTAuthentication
from cloudinary import uploader as cloud


# In-projects imports.
from .serializers import (
    ProductSerializers
)
from .models import Product


class ProductView(generics.CreateAPIView):
    serializer_class = ProductSerializers
    authentication_classes = [JWTAuthentication]
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, JSONParser)

    def create(self, request):
        user_data = request.data
        authenticated_user = request.user

        serializer = self.serializer_class(data=user_data)
        if serializer.is_valid(raise_exception=True):
            with ThreadPoolExecutor() as executor:
                # Submit files upload tasks to the thread pool.
                preview = executor.submit(
                    self.upload_assets, user_data.get("preview")
                )
                cover_image = executor.submit(
                    self.upload_assets, user_data.get("cover_image")
                )

                video_or_sound = executor.submit(
                    self.upload_assets, user_data.get("video_or_sound")
                )

                # Wait for both uploads to complete
                preview_url = preview.result()
                cover_image_url = cover_image.result()
                video_or_sound_url = video_or_sound.result()
            
                if preview_url and cover_image_url and video_or_sound:
                    product = Product.objects.create(
                        user=authenticated_user,
                        preview=preview_url,
                        title=user_data.get("title"),
                        price=user_data.get("price"),
                        cover_image=cover_image_url,
                        video_or_sound=video_or_sound
                    )
                    product.save()
                else:
                    return Response(
                        data="File upload failed, please try again later.",
                        status=status.HTTP_400_BAD_REQUEST
                    )
            response_data = {
                "status": "Success!",
                "message": "Product uoloaded successfully",
                "id": serializer.data["id"],
                "title": user_data.get("title"),
                "preview": preview_url,
                "cover_image": cover_image_url,
                "media_file": video_or_sound_url
            }
            return Response(data=response_data, status=status.HTTP_201_CREATED)

    def upload_assets(self, image_data):
        uploaded_image = cloud.upload(file=image_data)
        return uploaded_image["url"]


class RetrieveSingleProduct(generics.RetrieveAPIView):
    """
    RetrieveSingleProduct retrieves details of a single product.
    """
    queryset = Product.objects.all()
    serializer_class = ProductSerializers

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()

        serializer = self.get_serializer(instance)
        response_data = {
            "status": "Product details fetched successfully!",
            "data": serializer.data,
        }

        return Response(data=response_data, status=status.HTTP_200_OK)


class ListAllProducts(generics.ListAPIView):
    """
    ListAllProducts lists all the available product in the store.
    """
    serializer_class = ProductSerializers

    def list(self, request, *args, **kwargs):
        products = Product.objects.all()

        # Serialize the entire queryset once
        serialized_products = ProductSerializers(products, many=True).data

        response_data = {
            "status": "All products fetched successfully!",
            "data": serialized_products,
        }

        return Response(data=response_data, status=status.HTTP_200_OK)
    

