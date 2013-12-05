from requests import HTTPError
from openid.extensions import oauth

from social.backends.open_id import OpenIdAuth
from social.backends.oauth import BaseOAuth1
from social.exceptions import AuthCanceled, AuthUnknownError, AuthTokenError

class OpenIdOAuth1(OpenIdAuth, BaseOAuth1):
    oauth_ns_alias = 'oauth'
    oauth_data = None

    def extra_data(self, user, uid, response, details=None, *args, **kwargs):
        """Return extra data from both OpenId and OAuth"""
        openid_values = OpenIdAuth.extra_data(self, user, uid, response, details, *args, **kwargs)
        oauth_values = BaseOAuth1.extra_data(self, user, uid, self.oauth_data, *args, **kwargs)
        return dict(openid_values.items() + oauth_values.items())

    def auth_complete(self, *args, **kwargs):
        """Complete auth process"""
        response = self.consumer().complete(dict(self.data.items()),
                                            self.strategy.absolute_uri(
                                                self.redirect_uri
                                            ))
        self.process_error(response)

        oauth_response = oauth.OAuthResponse.fromSuccessResponse(response)
        oauth_token = {}
        if oauth_response:
            oauth_args = oauth_response.getExtensionArgs()
            oauth_token['oauth_token'] = oauth_args.get('request_token', '')
            if not oauth_token['oauth_token'] or oauth_token['oauth_token'] == '':
                raise AuthTokenError(self, 'Missing authorized token')
        else:
            raise AuthUnknownError(self, 'Could not get oauth response')

        try:
            access_token = self.access_token(oauth_token)
        except HTTPError as err:
            if err.response.status_code == 400:
                raise AuthCanceled(self)
            else:
                raise

        oauth_data = self.user_data(access_token)
        if oauth_data is not None and 'access_token' not in oauth_data:
            oauth_data['access_token'] = access_token
        self.oauth_data = oauth_data

        kwargs.update({'response': response, 'backend': self})
        return self.strategy.authenticate(*args, **kwargs)

    def setup_request(self, params=None):
        """Setup request"""
        request = OpenIdAuth.setup_request(self, params)
        key, secret = self.get_key_and_secret()
        scope = self.get_scope_argument().get(self.SCOPE_PARAMETER_NAME, '')
        oauth_request = oauth.OAuthRequest(self.oauth_ns_alias, key, scope)
        request.addExtension(oauth_request)
        return request
