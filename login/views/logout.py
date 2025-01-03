from django.contrib.auth import logout as auth_logout
from django.http import JsonResponse, HttpResponse
import logging

def logout(req):
    if not req.user.is_authenticated:
        logging.error('User not authenticated')
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    req.user.status = 'OF'
    req.user.save()
    logging.info(f'User {req.user.email} logged out')
    auth_logout(req)
    return HttpResponse(status=204)
