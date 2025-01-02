from django.http import JsonResponse, HttpResponse

def delete_user(req):
    if not req.user.is_authenticated:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    req.user.delete()
    return HttpResponse(status=204)
