from django.http import JsonResponse, HttpResponse
# from django.conf import settings
import requests
from ..models import Player
from django.contrib.auth import login
from .serializers import UserSerializer
import os


def get_oauth2_urls(provider):
    if provider == '42':
        return {
            'token_url': 'https://api.intra.42.fr/oauth/token',
            'userinfo_url': 'https://api.intra.42.fr/v2/me',
            'client_id': os.environ.get('SOCIAL_AUTH_42_OAUTH2_KEY'),
            'client_secret': os.environ.get('SOCIAL_AUTH_42_OAUTH2_SECRET'),
        }
    elif provider == 'google':
        return {
            'token_url': 'https://oauth2.googleapis.com/token',
            'userinfo_url': 'https://www.googleapis.com/oauth2/v1/userinfo',
            'client_id': os.environ.get('SOCIAL_AUTH_GOOGLE_OAUTH2_KEY'),
            'client_secret': os.environ.get('SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET')
        }
    else:
        raise ValueError('Invalid OAuth2 provider')

def create_user(user_info, provider):
    if provider == '42':
        user = Player.objects.create_user( # type: ignore
            username=user_info['login'],
            email=user_info['email'],
            first_name=user_info['first_name'],
            last_name=user_info['last_name'],
            avatar_url=user_info['image']['versions']['small']
        )
    else:  # google
        user = Player.objects.create_user( # type: ignore
            username=user_info['name'],
            email=user_info['email'],
            first_name=user_info['given_name'],
            last_name=user_info['family_name'],
            avatar_url=user_info['picture']
        )
    return user


def callback(req):
    if req.COOKIES.get('state') != req.GET.get('state'):
        return JsonResponse({'error': 'Invalid state'}, status=400)
    
    code = req.GET.get('code')
    if not code:
        return JsonResponse({'error': 'No code provided'}, status=400)
    
    try:
        oauth2_urls = get_oauth2_urls(req.COOKIES.get('oauth2_provider'))
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    if req.GET.get('error'):
        return JsonResponse({'error': req.GET.get('error'), 'error_description': req.GET.get('error_description')}, status=500)

    body = {
        "grant_type": "authorization_code",
        "client_id": oauth2_urls['client_id'],
        "client_secret": oauth2_urls['client_secret'],
        'code': code,
        "redirect_uri": str(os.environ.get('DOMAIN')) + '/account/login/callback/',
    }

    response = requests.post(url=oauth2_urls['token_url'], data=body)

    if response.status_code != 200:
        return JsonResponse({'error': response.json().get('error'), 'error_description': response.json().get('error_description')}, status=response.status_code)
    
    access_token = response.json().get('access_token')
    
    response = requests.get(url=oauth2_urls['userinfo_url'], headers={'Authorization': f'Bearer {access_token}'})
    if response.status_code != 200:
        return JsonResponse({'error': 'Failed to obtain user info'}, status=response.status_code)
    
    user_info = response.json()
    
    try:
        user = Player.objects.get(email=user_info['email'])
    except Player.DoesNotExist:
        user = create_user(user_info, req.COOKIES.get('oauth2_provider'))
    
    login(req, user)
    res = JsonResponse(UserSerializer(user).data, status=201)
    res.delete_cookie('state')
    return res

