from django.conf.urls import url, patterns

urlpatterns = patterns('twitterapp.views',
    url(r'^login/$', 'twitter_login', name='twitterapp_login'),
    url(r'^login-authentication/', 'login_authentication', name='twitterapp_login_authentication'),
    url(r'^logout/$', 'twitter_logout', name='twitterapp_logout')
)