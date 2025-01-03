from django.shortcuts import redirect
# from django.conf import settings
import secrets, os


def google_login(req):
    state = secrets.token_urlsafe(16)
    url = "https://accounts.google.com/o/oauth2/auth"
    url += f"?client_id={os.environ.get('SOCIAL_AUTH_GOOGLE_OAUTH2_KEY')}"
    url += f"&redirect_uri={os.environ.get('DOMAIN')}/account/login/callback/"
    url += "&response_type=code"
    url += "&scope=email profile"
    url += f"&state={state}"
    response = redirect(url)
    response.set_cookie('state', state, httponly=True, secure=True)
    response.set_cookie('oauth2_provider', 'google', httponly=True, secure=True)
    return response

def login_42(req):
    state = secrets.token_urlsafe(16)
    url = "https://api.intra.42.fr/oauth/authorize"
    url += f"?client_id={ os.environ.get('SOCIAL_AUTH_42_OAUTH2_KEY')}"
    url += f"&redirect_uri={os.environ.get('DOMAIN')}/account/login/callback/"
    url += "&response_type=code"
    url += f"&state={state}"
    response = redirect(url)
    response.set_cookie('state', state, httponly=True, secure=True)
    response.set_cookie('oauth2_provider', '42', httponly=True, secure=True)
    return response
