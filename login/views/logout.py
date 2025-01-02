from django.contrib.auth import logout as auth_logout
from django.http import JsonResponse, HttpResponse
import logging

def logout(req):
    if not req.user.is_authenticated:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    
    auth_logout(req)
    return HttpResponse(status=204)
