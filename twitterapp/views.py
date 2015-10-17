import logging
import urlparse
import oauth2 as oauth

from django.shortcuts import render
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect
from django.conf import settings
from django.contrib.auth.decorators import login_required

from TwitterAuth.constants import REQUEST_TOKEN_URL, AUTHORIZE_URL, ACCESS_TOKEN_URL
from twitterapp.models import UserProfile


consumer = oauth.Consumer(settings.TWITTER_CONSUMER_KEY, settings.TWITTER_SECRET_KEY)
client = oauth.Client(consumer)
log = logging.getLogger('console')


def twitter_login(request):

    # Get a request token from Twitter
    response, content = client.request(REQUEST_TOKEN_URL, "GET")
    log.debug('TWITTER REQUEST TOKEN RESPONSE : {}, CONTENT:{}'.format(response, content))
    if response['status'] != '200':
        raise Exception("Invalid response from Twitter")

    # Store request token in session for later use
    request.session['request_token'] = dict(urlparse.parse_qsl(content))

    # Redirect user to authentication url
    url = '{}?oauth_token={}'.format(AUTHORIZE_URL, request.session['request_token']['oauth_token'])
    return HttpResponseRedirect(url)


def login_authentication(request):
    log.info('TWITTER CALL BACK PARAMS : {}'.format(request.GET))
    # Create new client using request token in the session
    token = oauth.Token(request.session['request_token']['oauth_token'],
                        request.session['request_token']['oauth_token_secret'],
                        )
    token.set_verifier(request.GET['oauth_verifier'])

    client = oauth.Client(consumer, token)

    # Request authorized access token from twitter
    response, content = client.request(ACCESS_TOKEN_URL, "GET")
    log.debug('TWITTER ACCESS TOKEN RESPONSE : {}, CONTENT:{}'.format(response, content))
    if response['status'] != '200':
        raise Exception("Invalid response from Twitter")

    access_token = dict(urlparse.parse_qsl(content))
    # Create new user if it is not existing
    try:
        user = User.objects.get(username=access_token['screen_name'])
    except User.DoesNotExist:
        user = User.objects.create_user(access_token['screen_name'],
                                        '{}@twitter.com'.format(access_token['screen_name']),
                                        access_token['oauth_token_secret'])

        # Save permanent token & secret for future purpose
        profile = UserProfile()
        profile.user = user
        profile.oauth_token = access_token['oauth_token']
        profile.oauth_secret = access_token['oauth_token_secret']
        profile.save()

    # Authenticate & login using django's built-in function
    user = authenticate(username=access_token['screen_name'],
                        password=access_token['oauth_token_secret'])
    login(request, user)
    return HttpResponseRedirect('/')


@login_required
def twitter_logout(request):
    logout(request)
    return HttpResponseRedirect('/')