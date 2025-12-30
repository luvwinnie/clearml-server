"""
OIDC (OpenID Connect) service endpoints for SSO authentication.
"""
from urllib.parse import urljoin

from apiserver.apierrors import errors
from apiserver.bll.auth import AuthBLL
from apiserver.bll.auth.oidc import (
    get_provider_by_name,
    build_authorization_url,
    generate_state,
    generate_nonce,
    exchange_code_for_tokens,
    validate_id_token,
    extract_user_info,
    get_or_create_user,
)
from apiserver.config_repo import config
from apiserver.service_repo import APICall, endpoint

log = config.logger(__file__)

# Simple in-memory state storage (in production, use Redis or similar)
# Maps state -> {nonce, provider, redirect_uri, timestamp}
_pending_auth_states = {}


def _get_callback_uri(call: APICall, provider_name: str) -> str:
    """Generate the callback URI based on the request host"""
    # Use the configured redirect_uri if available
    provider = get_provider_by_name(provider_name)
    if provider and provider.redirect_uri:
        return provider.redirect_uri

    # Otherwise, generate from request host
    host = call.host or "localhost"
    scheme = "https" if "ngrok" in host or ":" not in host else "http"
    base_url = f"{scheme}://{host}"
    return urljoin(base_url, f"/api/v2.23/oidc.callback?provider={provider_name}")


@endpoint("oidc.authorize")
def authorize(call: APICall, _, __):
    """
    Initiate OIDC authorization flow.
    Redirects user to the identity provider for authentication.
    """
    provider_name = call.data.get("provider", "authentik")
    redirect_uri_override = call.data.get("redirect_uri")

    provider = get_provider_by_name(provider_name)
    if not provider:
        raise errors.bad_request.InvalidId(
            f"Unknown OIDC provider: {provider_name}",
            provider=provider_name,
        )

    # Generate state and nonce for security
    state = generate_state()
    nonce = generate_nonce()

    # Determine callback URI
    callback_uri = redirect_uri_override or _get_callback_uri(call, provider_name)

    # Store state for later validation
    _pending_auth_states[state] = {
        "nonce": nonce,
        "provider": provider_name,
        "redirect_uri": callback_uri,
    }

    # Build authorization URL
    auth_url = build_authorization_url(
        provider=provider,
        redirect_uri=callback_uri,
        state=state,
        nonce=nonce,
    )

    log.info(f"Initiating OIDC auth for provider {provider_name}, redirecting to IdP")

    # Return the URL for the client to redirect to
    call.result.data = {"url": auth_url}

    # Also set up redirect in case the endpoint is called directly
    call.result.redirect = auth_url


@endpoint("oidc.callback")
def callback(call: APICall, _, __):
    """
    Handle OIDC callback from identity provider.
    Exchanges authorization code for tokens and creates/authenticates user.
    """
    provider_name = call.data.get("provider", "authentik")
    code = call.data.get("code")
    state = call.data.get("state")
    error = call.data.get("error")
    error_description = call.data.get("error_description", "")

    # Check for errors from IdP
    if error:
        log.error(f"OIDC error from IdP: {error} - {error_description}")
        raise errors.unauthorized.InvalidCredentials(
            f"Authentication failed: {error_description or error}"
        )

    if not code:
        raise errors.bad_request.MissingRequiredFields("Missing authorization code")

    # Validate state
    if not state or state not in _pending_auth_states:
        log.error(f"Invalid or missing state parameter: {state}")
        raise errors.unauthorized.InvalidCredentials(
            "Invalid state parameter. Please try logging in again."
        )

    state_data = _pending_auth_states.pop(state)
    nonce = state_data.get("nonce")
    redirect_uri = state_data.get("redirect_uri")

    # Get provider configuration
    provider = get_provider_by_name(provider_name)
    if not provider:
        raise errors.bad_request.InvalidId(
            f"Unknown OIDC provider: {provider_name}",
            provider=provider_name,
        )

    try:
        # Exchange code for tokens
        log.info(f"Exchanging authorization code for tokens with provider {provider_name}")
        tokens = exchange_code_for_tokens(
            provider=provider,
            code=code,
            redirect_uri=redirect_uri,
        )

        # Validate ID token
        log.info("Validating ID token")
        claims = validate_id_token(
            provider=provider,
            id_token=tokens.id_token,
            nonce=nonce,
        )

        # Extract user info from claims
        user_info = extract_user_info(provider, claims)
        log.info(f"OIDC user info: username={user_info.username}, email={user_info.email}")

        # Get or create user
        user = get_or_create_user(provider, user_info)

        # Generate ClearML token for the user
        token_response = AuthBLL.get_token_for_user(
            user_id=user.id,
            company_id=user.company,
        )

        # Set auth cookie
        call.result.set_auth_cookie(token_response.token)

        log.info(f"OIDC login successful for user {user.id}")

        # Redirect to the web UI
        host = call.host or "localhost"
        scheme = "https" if "ngrok" in host or ":" not in host else "http"

        # Get the subpath from config (default to /clearml/ for reverse proxy setups)
        # This matches how the API is accessed: /clearml/api/ -> web UI at /clearml/
        subpath = config.get("webserver.subpath", "/clearml")
        if not subpath.startswith("/"):
            subpath = "/" + subpath
        if not subpath.endswith("/"):
            subpath = subpath + "/"

        # Redirect to the main ClearML page
        # The cookie will be set, so user will be authenticated
        redirect_url = f"{scheme}://{host}{subpath}"

        call.result.redirect = redirect_url
        call.result.data = {
            "user": user.id,
            "token": token_response.token,
        }

    except Exception as e:
        log.error(f"OIDC callback error: {e}")
        raise
