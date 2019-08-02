import logging
import requests
import ssl
from flask import redirect, url_for, Blueprint, flash, request, session
from flask_oauthlib.client import OAuth, prepare_request, http

from redash import models, settings
from redash.authentication import create_and_login_user, logout_and_redirect_to_index, get_next_path
from redash.authentication.org_resolving import current_org

logger = logging.getLogger('WSO2_oauth')

oauth = OAuth()
blueprint = Blueprint('WSO2_oauth', __name__)

def net_http_request(uri, headers=None, data=None, method=None):
    '''
    Method for monkey patching 'flask_oauthlib.client.OAuth.http_request'
    This version allows for insecure SSL certificates
    '''
    uri, headers, data, method = prepare_request(
        uri, headers, data, method
    )
    req = http.Request(uri, headers=headers, data=data)
    req.get_method = lambda: method.upper()
    try:
        resp = http.urlopen(req, context=ssl._create_unverified_context())
        content = resp.read()
        resp.close()
        return resp, content
    except http.HTTPError as resp:
        content = resp.read()
        resp.close()
        return resp, content

def WSO2_remote_app():
    if 'WSO2' not in oauth.remote_apps:
        oauth.remote_app('WSO2',
                         base_url='https://192.168.99.100:9445',
                         authorize_url='https://192.168.99.100:9445/oauth2/authorize',
                         request_token_url=None,
                         request_token_params={'scope': 'openid'},
                         access_token_url='https://192.168.99.100:9445/oauth2/token',
                         access_token_method='POST',
                         consumer_key='98jT9dO6BlR8UsdBr1lnTqNOZWQa',
                         consumer_secret='N80UgtjoEdyqtsq9h3SYd2HMtuQa',
                         ).http_request = net_http_request


#consumer_key=settings.WSO2_CLIENT_ID,
#consumer_secret=settings.WSO2_CLIENT_SECRET)

    return oauth.WSO2


def get_user_profile(access_token):
    print("\n\n\n\n\n\n\n",access_token,"\n\n\n\n\n\n\n");
    headers = {'Authorization': 'Bearer {}'.format(access_token)}
    #print(headers)
    response = requests.get('https://192.168.99.100:9445/oauth2/userinfo', headers=headers,verify=False)

    if response.status_code == 401:
        logger.warning("Failed getting user profile (response code 401).")
        return None

    return response.json()


def verify_profile(org, profile):
    if org.is_public:
        return True

    print(profile)

    email = profile['email']
    #email = "callari89@asd.com"
    domain = email.split('@')[-1]

    print(org)
    print(domain)
    print(org.wso2_apps_domains)
    print(org.has_user(email))

    if domain in org.wso2_apps_domains:
        return True

    if org.has_user(email) == 1:
        return True

    return False


@blueprint.route('/<org_slug>/oauth/WSO2', endpoint="authorize_org")
def org_login(org_slug):
    session['org_slug'] = current_org.slug
    return redirect(url_for(".authorize", next=request.args.get('next', None)))


@blueprint.route('/oauth/WSO2', endpoint="authorize")
def login():
    callback = url_for('.callback', _external=True)
    next_path = request.args.get('next', url_for("redash.index", org_slug=session.get('org_slug')))
    logger.debug("Callback url: %s", callback)
    logger.debug("Next is: %s", next_path)
    return WSO2_remote_app().authorize(callback=callback, state=next_path)


@blueprint.route('/oauth/WSO2_callback', endpoint="callback")
def authorized():
    resp = WSO2_remote_app().authorized_response()
    access_token = resp['access_token']

    if access_token is None:
        logger.warning("Access token missing in call back request.")
        flash("Validation error. Please retry.")
        return redirect(url_for('redash.login'))

    profile = get_user_profile(access_token)
    if profile is None:
        flash("Validation error. Please retry.")
        return redirect(url_for('redash.login'))

    if 'org_slug' in session:
        org = models.Organization.get_by_slug(session.pop('org_slug'))
    else:
        org = current_org

    if not verify_profile(org, profile):
        logger.warning("User tried to login with unauthorized domain name: %s (org: %s)", profile['email'], org)
        flash("Your WSO2 Apps account ({}) isn't allowed.".format(profile['email']))
        return redirect(url_for('redash.login', org_slug=org.slug))

    #picture_url = "https://avatars2.githubusercontent.com/u/6839125?s=40&v=4"
    #user = create_and_login_user(org, "Geltrudo Antico", "callari89@asd.com", picture_url)
    picture_url = "%s" % profile['avatar_url']
    user = create_and_login_user(org, profile['name'], profile['email'], picture_url)
    if user is None:
        return logout_and_redirect_to_index()

    unsafe_next_path = request.args.get('state') or url_for("redash.index", org_slug=org.slug)
    next_path = get_next_path(unsafe_next_path)

    return redirect(next_path)