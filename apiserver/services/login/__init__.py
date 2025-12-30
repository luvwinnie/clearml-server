from apiserver.apimodels.login import (
    GetSupportedModesRequest,
    GetSupportedModesResponse,
    BasicMode,
    BasicGuestMode,
    ServerErrors,
)
from apiserver.bll.auth.oidc import get_oidc_providers, is_oidc_enabled
from apiserver.config import info
from apiserver.service_repo import endpoint, APICall
from apiserver.service_repo.auth import revoke_auth_token
from apiserver.service_repo.auth.fixed_user import FixedUser


def _get_sso_providers_list(host: str = None) -> list:
    """
    Build the list of SSO providers for the login page.
    Returns a list of dicts with name, url, and display_name.
    """
    if not is_oidc_enabled():
        return []

    providers = get_oidc_providers()
    sso_list = []

    for provider in providers:
        # Build the authorization URL for each provider
        # The frontend will redirect to this URL when the user clicks the SSO button
        scheme = "https" if host and ("ngrok" in host or ":" not in host) else "http"
        base_url = f"{scheme}://{host}" if host else ""

        sso_list.append({
            "name": provider.name,
            "url": f"{base_url}/clearml/api/v2.23/oidc.authorize?provider={provider.name}",
            "display_name": provider.display_name,
        })

    return sso_list


@endpoint("login.supported_modes", response_data_model=GetSupportedModesResponse)
def supported_modes(call: APICall, _, __: GetSupportedModesRequest):
    guest_user = FixedUser.get_guest_user()
    if guest_user:
        guest = BasicGuestMode(
            enabled=True,
            name=guest_user.name,
            username=guest_user.username,
            password=guest_user.password,
        )
    else:
        guest = BasicGuestMode()

    # Get SSO providers if OIDC is enabled
    sso_providers = _get_sso_providers_list(call.host)

    return GetSupportedModesResponse(
        basic=BasicMode(enabled=FixedUser.enabled(), guest=guest),
        sso={},  # Legacy field, kept for compatibility
        sso_providers=sso_providers,
        server_errors=ServerErrors(
            missed_es_upgrade=info.missed_es_upgrade,
            es_connection_error=info.es_connection_error,
        ),
        authenticated=call.auth is not None,
    )


@endpoint("login.logout", min_version="2.13")
def logout(call: APICall, _, __):
    revoke_auth_token(call.auth)
    call.result.set_auth_cookie(None)
