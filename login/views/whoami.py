from django.http import JsonResponse
from .serializers import UserSerializer
import logging

def whoami(req):
    if not req.user.is_authenticated:
        logging.error('User not authenticated')
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    logging.info(f'User {req.user.email} accessed whoami endpoint')
    return JsonResponse(UserSerializer(req.user).data, status=200)
