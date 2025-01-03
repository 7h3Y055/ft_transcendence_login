from django.http import JsonResponse, HttpResponse
import logging

def delete_user(req):
    if not req.user.is_authenticated:
        logging.warning("Unauthorized request to delete user")
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    req.user.delete()
    logging.info(f'Delete user {req.user.email}')
    return HttpResponse(status=204)
