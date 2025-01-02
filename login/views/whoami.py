from django.http import JsonResponse
from .serializers import UserSerializer
import logging

def whoami(req):
    if not req.user.is_authenticated:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    
    return JsonResponse(UserSerializer(req.user).data, status=200)
