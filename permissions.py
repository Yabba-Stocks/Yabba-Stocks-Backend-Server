from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied


class IsVerifiedUser(permissions.BasePermission):
    """
    Custom permission to only allow verified users to access the view.
    """

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return True
        
        if request.user.is_verified:
            return True
        else:
            raise PermissionDenied("Only verified users can login.")
