import json
import base64
import logging
import pdb
from Products.Five.browser import BrowserView
from oic.oic.message import AuthorizationResponse
from oic.oic.message import EndSessionRequest
from oic import rndstr
from plone import api
from hashlib import sha256
import base64

logger = logging.getLogger(__name__)


# https://zope.readthedocs.io/en/latest/zopebook/Sessions.html#alternative-server-side-session-backends-for-zope-4
# in produzione usare: https://pypi.org/project/Products.mcdutils/
# XXX: attualmente implementata sessione su cookie
class Session(object):
    session_cookie_name = "__ac_session"
    _session = {}

    def __init__(self, request, use_session_data_manager=False):
        self.request = request
        self.use_session_data_manager = use_session_data_manager
        if self.use_session_data_manager:
            sdm = api.portal.get_tool("session_data_manager")
            self._session = sdm.getSessionData(create=True)
        else:
            data = self.request.cookies.get(self.session_cookie_name) or {}
            if data:
                data = json.loads(base64.b64decode(data))
            self._session = data

    def set(self, name, value):
        if self.use_session_data_manager:
            self._session.set(name, value)
        else:
            if self.get(name) != value:
                self._session[name] = value
                self.request.response.setCookie(
                    self.session_cookie_name,
                    base64.b64encode(json.dumps(self._session).encode("utf-8")),
                )

    def get(self, name):
        # if self.use_session_data_manager:
        return self._session.get(name)

    def __repr__(self):
        return repr(self._session)


class LoginView(BrowserView):
    def __call__(self):
        session = Session(
            self.request, use_session_data_manager=self.context.use_session_data_manager
        )
        # state is used to keep track of responses to outstanding requests (state).
        # nonce is a string value used to associate a Client session with an ID Token, and to mitigate replay attacks.
        session.set("state", rndstr())
        session.set("nonce", rndstr())
        session.set("verifier", rndstr(size=128))
        client = self.context.get_oauth2_client()

        # https://pyoidc.readthedocs.io/en/latest/examples/rp.html#authorization-code-flow
        args = {
            "client_id": self.context.client_id,
            "response_type": "code",
            "scope": self.context.get_scopes(),
            "state": session.get("state"),
            "redirect_uri": self.context.get_redirect_uris()[0],
            "code_challenge": self.get_code_challenge(value=session.get("verifier")),
            "code_challenge_method": "S256",
        }
        print(args)
        auth_req = client.construct_AuthorizationRequest(request_args=args)
        login_url = auth_req.request(client.authorization_endpoint)
        self.request.response.setHeader("Cache-Control", "no-cache, must-revalidate")
        self.request.response.redirect(login_url)
        return

    def get_code_challenge(self, value):
        """build a sha256 hash of the base64 encoded value of value"""
        hash_code = sha256(value.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(hash_code).decode("utf-8").replace("=", "")


class LogoutView(BrowserView):
    def __call__(self):
        client = self.context.get_oauth2_client()
        # session = Session(self.request, use_session_data_manager=self.context.use_session_data_manager)
        # state is used to keep track of responses to outstanding requests (state).
        # https://github.com/keycloak/keycloak-documentation/blob/master/securing_apps/topics/oidc/java/logout.adoc
        # session.set('end_session_state', rndstr())
        args = {
            # 'state': session.get('end_session_state'),
            # TODO: ....
            # 'post_logout_redirect_uri': api.portal.get().absolute_url(),
            "redirect_uri": api.portal.get().absolute_url(),
        }
        # end_req = client.construct_EndSessionRequest(request_args=args)
        end_req = EndSessionRequest(**args)
        logout_url = end_req.request(client.end_session_endpoint)
        self.request.response.setHeader("Cache-Control", "no-cache, must-revalidate")
        self.request.response.expireCookie("__ac", path="/")
        self.request.response.expireCookie("auth_token", path="/")
        self.request.response.redirect(logout_url)
        return


class CallbackView(BrowserView):
    def __call__(self):
        response = self.request.environ["QUERY_STRING"]
        session = Session(
            self.request, use_session_data_manager=self.context.use_session_data_manager
        )
        client = self.context.get_oauth2_client()
        aresp = client.parse_response(
            AuthorizationResponse, info=response, sformat="urlencoded"
        )
        # XXX: togliere debug e reinserire assert dopo aver trovato eventuali
        # anomalie
        logger.info("DEBUG %s %s", aresp.get("state"), session.get("state"))
        # assert aresp["state"] == session.get("state")

        args = {
            "grant_type": "authorization_code",
            "code": aresp["code"],
            "redirect_uri": self.context.get_redirect_uris()[0],
            "code_verifier": session.get("verifier"),
            "refresh_token_max_age": 14400,
            "id_token_max_age": 14400,
            "versioned_uid_required": False,
        }

        # "email_verified" atributua ez dator ondo serializatuta. Hori konpontzen bada
        # plugina tal cual erabili daiteke email scope-a adieraziz. Konpontzen duten bitartean
        # requests-ekin eskatzen da tokena eta eskuz deskodetu jwt-a
        """
        resp = client.do_access_token_request(
            state=aresp["state"], request_args=args, authn_method="client_secret_basic"
        )
        """
        import requests

        auth = base64.b64encode(
            f"{self.context.client_id}:{self.context.client_secret}".encode("utf-8")
        ).decode()
        auth_headers = {"Authorization": f"Basic {auth}"}
        token_endpoint_url = "https://ecas.acceptance.ec.europa.eu/cas/oauth2/token"
        resp = requests.post(token_endpoint_url, data=args, headers=auth_headers)
        if resp.status_code == 200:
            userinfo = self.jwt_payload_decode(resp.json().get("id_token"))
        else:
            pass
        # session.set('id_token', )
        self.context.rememberIdentity(userinfo)
        # TODO: manage next_url/came_from
        self.request.response.setHeader("Cache-Control", "no-cache, must-revalidate")
        self.request.response.redirect(api.portal.get().absolute_url())
        # return userinfo.to_json()
        return

    def _b64_decode(self, data):
        data += "=" * (4 - len(data) % 4)
        return base64.b64decode(data).decode("utf-8")

    def jwt_payload_decode(self, jwt):
        _, payload, _ = jwt.split(".")
        return json.loads(self._b64_decode(payload))
