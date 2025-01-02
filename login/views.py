from django.shortcuts import render
from django.shortcuts import redirect
import requests
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.contrib.auth import login, logout as auth_logout
from .models import Player

# Create your views here.

def google_login(req):
    url = "https://accounts.google.com/o/oauth2/auth"
    url += f"?client_id={settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY}"
    url += f"&redirect_uri={settings.DOMAIN}/account/login/callback/"
    url += "&response_type=code"
    url += "&scope=email profile"
    res = redirect(url)
    req.session['oauth2_provider'] = 'google'
    return res

def login_42(req):
    url = "https://api.intra.42.fr/oauth/authorize"
    url += f"?client_id={settings.SOCIAL_AUTH_42_OAUTH2_KEY}"
    url += f"&redirect_uri={settings.DOMAIN}/account/login/callback/"
    url += "&response_type=code"
    res = redirect(url)
    req.session['oauth2_provider'] = '42'
    return res

def create_user(user_info, provider):
    if provider == '42':
        User = Player.objects.create_user( # type: ignore
            username=user_info['login'],
            email=user_info['email'],
            first_name=user_info['first_name'],
            last_name=user_info['last_name'],
            avatar_url=user_info['image']['versions']['small']
        )
    else: # google
        User = Player.objects.create_user( # type: ignore
            username=user_info['name'],
            email=user_info['email'],
            first_name=user_info['given_name'],
            last_name=user_info['family_name'],
            avatar_url=user_info['picture']
        )
    return User

def generate_random_hash():
    pass

def callback(req):
    code = req.GET.get('code')
    if not code:
        return JsonResponse({'error': 'No code provided'}, status=400)
    
    if req.session['oauth2_provider'] == '42':
        token_url = 'https://api.intra.42.fr/oauth/token'
        userinfo_url = 'https://api.intra.42.fr/v2/me'
        OAUTH2_ID = settings.SOCIAL_AUTH_42_OAUTH2_KEY
        OAUTH2_SECRET = settings.SOCIAL_AUTH_42_OAUTH2_SECRET
    elif req.session['oauth2_provider'] == 'google':
        token_url = 'https://oauth2.googleapis.com/token'
        userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
        OAUTH2_ID = settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY
        OAUTH2_SECRET = settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET
    else:
        return JsonResponse({'error': 'Invalid OAuth2 provider'}, status=500)
    
    # check if there any error
    if req.GET.get('error'):
        return JsonResponse({'error': req.GET.get('error'), 'error_description': req.GET.get('error_description')}, status=500)

    # get access token
    body = {
        "grant_type": "authorization_code",
        "client_id": OAUTH2_ID,
        "client_secret": OAUTH2_SECRET,
        'code': code,
        "redirect_uri": settings.DOMAIN + '/account/login/callback/',
        # 'state': '123'
    }
    response = requests.post(url=token_url, data=body)

    if 'access_token' in response.json():
        access_token = response.json()['access_token']
    elif 'error' in response.json():
        return JsonResponse({'error': response.json()['error'], 'error_description': response.json()['error_description']}, status=500)
    else:
        return JsonResponse({'error': 'Failed to obtain access token'}, status=500)
    
    response = requests.get(url=userinfo_url, headers={'Authorization': f'Bearer {access_token}'})
    if response.status_code != 200:
        return JsonResponse({'error': 'Failed to obtain user info'}, status=response.status_code)
    user_info = response.json()
    
    
    try:
        User = Player.objects.get(email=user_info['email'])
    except Player.DoesNotExist:
        User = create_user(user_info, req.session['oauth2_provider'])
    
    login(req, User)
    user_data = {
        'id': User.id,
        'username': User.username,
        'email': User.email,
        'first_name': User.first_name,
        'last_name': User.last_name,
        'avatar_url': User.avatar_url,
        'status': User.status,
        'two_FA': User.two_FA,
        'created_at': User.created_at,
    }
    return JsonResponse(user_data, status=201)

def whoami(req):
    if not req.user.is_authenticated:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    user_data = {
        'id':  req.user.id,
        'username':  req.user.username,
        'email':  req.user.email,
        'first_name':  req.user.first_name,
        'last_name':  req.user.last_name,
        'avatar_url':  req.user.avatar_url,
        'status':  req.user.status,
        'two_FA':  req.user.two_FA,
        'created_at':  req.user.created_at,
    }
    return JsonResponse(user_data, status=200)


def logout(req):
    if not req.user.is_authenticated:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    auth_logout(req)
    return HttpResponse(status=204)

def delete_user(req):
    if not req.user.is_authenticated:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    req.user.delete()
    return HttpResponse(status=204)

def avatar_upload(req):
    if not req.user.is_authenticated:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    if req.method == 'POST':
        req.user.avatar_url = req.FILES['avatar']
        req.user.save()
    return redirect('http://localhost:8000/account/')




def test(req):
    return render(req, 'test.html', {'user': req.user})