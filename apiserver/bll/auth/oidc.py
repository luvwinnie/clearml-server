"""
OIDC (OpenID Connect) authentication utilities for ClearML Server.
Handles OIDC discovery, token exchange, and user management.
"""
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any, List
from urllib.parse import urlencode, urljoin, urlparse

import jwt
import requests
from jwt import PyJWKClient

from apiserver import database
from apiserver.apierrors import errors
from apiserver.config_repo import config
from apiserver.database.errors import translate_errors_context
from apiserver.database.model.auth import User as AuthUser, Role, Credentials
from apiserver.database.model.user import User as BackendUser
from apiserver.database.model.company import Company
from apiserver.service_repo.auth import get_client_id, get_secret_key

log = config.logger("OIDC")

# Cache for OIDC discovery documents
_discovery_cache: Dict[str, Dict[str, Any]] = {}

# Cache for JWKS clients
_jwks_clients: Dict[str, PyJWKClient] = {}


@dataclass
class OIDCProvider:
    """OIDC Provider configuration"""
    name: str
    display_name: str
    issuer: str  # The issuer URL that appears in JWT tokens (used for validation)
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: List[str]
    claims: Dict[str, str]
    # Internal issuer URL for discovery (when running in Docker and external URL is not reachable)
    # If not set, uses the main issuer URL
    internal_issuer: Optional[str] = None
    # Public issuer URL for browser redirects (when issuer is internal Docker URL)
    # If not set, uses the main issuer URL
    public_issuer: Optional[str] = None


@dataclass
class OIDCTokens:
    """OIDC tokens returned from token endpoint"""
    access_token: str
    id_token: str
    token_type: str
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None


@dataclass
class OIDCUserInfo:
    """User information extracted from OIDC claims"""
    subject: str
    username: str
    email: Optional[str]
    name: Optional[str]
    given_name: Optional[str]
    family_name: Optional[str]


def get_oidc_config() -> Dict[str, Any]:
    """Get OIDC configuration from server config"""
    return config.get("services.auth.oidc", {})


def is_oidc_enabled() -> bool:
    """Check if OIDC is enabled"""
    oidc_config = get_oidc_config()
    enabled = oidc_config.get("enabled", False)
    if isinstance(enabled, str):
        return enabled.lower() in ("true", "1", "yes")
    return bool(enabled)


def get_oidc_providers() -> List[OIDCProvider]:
    """Get list of configured OIDC providers"""
    if not is_oidc_enabled():
        return []

    oidc_config = get_oidc_config()
    providers = []

    # Handle both list format and ConfigTree with numeric keys (from env vars)
    providers_conf = oidc_config.get("providers", [])

    # If providers is a dict-like ConfigTree with numeric keys, convert to list of values
    if hasattr(providers_conf, 'values'):
        providers_list = list(providers_conf.values())
    elif isinstance(providers_conf, list):
        providers_list = providers_conf
    else:
        providers_list = []

    for provider_conf in providers_list:
        # Skip providers without required fields
        if not provider_conf.get("issuer") or not provider_conf.get("client_id"):
            continue

        claims = provider_conf.get("claims", {})
        providers.append(OIDCProvider(
            name=provider_conf.get("name", "oidc"),
            display_name=provider_conf.get("display_name", "Login with SSO"),
            issuer=provider_conf.get("issuer"),
            client_id=provider_conf.get("client_id"),
            client_secret=provider_conf.get("client_secret", ""),
            redirect_uri=provider_conf.get("redirect_uri", ""),
            scopes=provider_conf.get("scopes", ["openid", "profile", "email"]),
            claims={
                "username": claims.get("username", "preferred_username"),
                "email": claims.get("email", "email"),
                "name": claims.get("name", "name"),
            },
            internal_issuer=provider_conf.get("internal_issuer"),
            public_issuer=provider_conf.get("public_issuer"),
        ))

    return providers


def get_provider_by_name(name: str) -> Optional[OIDCProvider]:
    """Get a specific OIDC provider by name"""
    for provider in get_oidc_providers():
        if provider.name == name:
            return provider
    return None


def discover_oidc_config(issuer: str, internal_issuer: Optional[str] = None) -> Dict[str, Any]:
    """
    Fetch OIDC discovery document from issuer's well-known endpoint.
    Results are cached.

    Args:
        issuer: The public issuer URL (used for caching and as fallback)
        internal_issuer: Optional internal URL to use for fetching (e.g., Docker network URL)
    """
    if issuer in _discovery_cache:
        return _discovery_cache[issuer]

    # Use internal_issuer for the actual HTTP request if provided
    fetch_url_base = internal_issuer or issuer
    discovery_url = urljoin(fetch_url_base.rstrip("/") + "/", ".well-known/openid-configuration")

    try:
        response = requests.get(discovery_url, timeout=10)
        response.raise_for_status()
        discovery_doc = response.json()
        _discovery_cache[issuer] = discovery_doc
        log.info(f"Fetched OIDC discovery document from {discovery_url}")
        return discovery_doc
    except requests.RequestException as e:
        log.error(f"Failed to fetch OIDC discovery document from {discovery_url}: {e}")
        raise errors.server_error.GeneralError(
            f"Failed to fetch OIDC configuration from {issuer}"
        )


def get_jwks_client(issuer: str, internal_issuer: Optional[str] = None) -> PyJWKClient:
    """Get or create a JWKS client for the issuer"""
    if issuer in _jwks_clients:
        return _jwks_clients[issuer]

    discovery = discover_oidc_config(issuer, internal_issuer)
    jwks_uri = discovery.get("jwks_uri")

    if not jwks_uri:
        raise errors.server_error.GeneralError(
            f"No jwks_uri found in OIDC discovery for {issuer}"
        )

    # The discovery document returns URLs with the internal host (since we fetched from internal_issuer).
    # JWKS should use the internal URL for server-to-server communication.
    # No replacement needed - the jwks_uri from discovery already has the internal host.
    log.info(f"Using JWKS URI: {jwks_uri}")

    client = PyJWKClient(jwks_uri)
    _jwks_clients[issuer] = client
    return client


def generate_state() -> str:
    """Generate a random state parameter for OIDC flow"""
    return secrets.token_urlsafe(32)


def generate_nonce() -> str:
    """Generate a random nonce for OIDC flow"""
    return secrets.token_urlsafe(32)


def _get_host_with_scheme(url: str) -> str:
    """Extract scheme://host:port from a URL"""
    parsed = urlparse(url)
    port_str = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    return f"{parsed.scheme}://{parsed.hostname}{port_str}"


def build_authorization_url(
    provider: OIDCProvider,
    redirect_uri: str,
    state: str,
    nonce: str,
) -> str:
    """Build the authorization URL for initiating OIDC flow"""
    discovery = discover_oidc_config(provider.issuer, provider.internal_issuer)
    auth_endpoint = discovery.get("authorization_endpoint")

    if not auth_endpoint:
        raise errors.server_error.GeneralError(
            f"No authorization_endpoint found for {provider.issuer}"
        )

    # The authorization endpoint must be the browser-facing URL (external),
    # not the internal Docker URL, because users' browsers need to navigate to it.
    # If we have a public_issuer configured, use it to replace the internal URL host.
    # This handles the case where:
    # - issuer = internal URL (what's in JWT tokens)
    # - internal_issuer = same internal URL (for HTTP requests)
    # - public_issuer = external URL (for browser redirects)
    public_issuer = provider.public_issuer or provider.issuer
    internal_issuer = provider.internal_issuer or provider.issuer

    if internal_issuer != public_issuer:
        internal_host = _get_host_with_scheme(internal_issuer)
        public_host = _get_host_with_scheme(public_issuer)
        if internal_host in auth_endpoint:
            auth_endpoint = auth_endpoint.replace(internal_host, public_host)
            log.info(f"Using public authorization endpoint: {auth_endpoint}")

    params = {
        "client_id": provider.client_id,
        "response_type": "code",
        "scope": " ".join(provider.scopes),
        "redirect_uri": redirect_uri,
        "state": state,
        "nonce": nonce,
    }

    return f"{auth_endpoint}?{urlencode(params)}"


def exchange_code_for_tokens(
    provider: OIDCProvider,
    code: str,
    redirect_uri: str,
) -> OIDCTokens:
    """Exchange authorization code for tokens"""
    discovery = discover_oidc_config(provider.issuer, provider.internal_issuer)
    token_endpoint = discovery.get("token_endpoint")

    if not token_endpoint:
        raise errors.server_error.GeneralError(
            f"No token_endpoint found for {provider.issuer}"
        )

    # The discovery document returns URLs with the internal host (since we fetched from internal_issuer).
    # Token exchange should use the internal URL for server-to-server communication.
    # No replacement needed - the token_endpoint from discovery already has the internal host.
    log.info(f"Using token endpoint: {token_endpoint}")

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": provider.client_id,
        "client_secret": provider.client_secret,
    }

    try:
        response = requests.post(
            token_endpoint,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        response.raise_for_status()
        token_data = response.json()

        return OIDCTokens(
            access_token=token_data.get("access_token", ""),
            id_token=token_data.get("id_token", ""),
            token_type=token_data.get("token_type", "Bearer"),
            expires_in=token_data.get("expires_in"),
            refresh_token=token_data.get("refresh_token"),
        )
    except requests.RequestException as e:
        log.error(f"Failed to exchange code for tokens: {e}")
        raise errors.unauthorized.InvalidCredentials(
            "Failed to exchange authorization code"
        )


def validate_id_token(
    provider: OIDCProvider,
    id_token: str,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate and decode an ID token"""
    try:
        jwks_client = get_jwks_client(provider.issuer, provider.internal_issuer)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)

        # Decode and validate the token
        # NOTE: The issuer claim in the token is the PUBLIC issuer URL (not internal),
        # so we validate against provider.issuer, not internal_issuer
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=provider.client_id,
            issuer=provider.issuer,
            options={
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            }
        )

        # Verify nonce if provided
        if nonce and claims.get("nonce") != nonce:
            raise errors.unauthorized.InvalidCredentials("Invalid nonce in ID token")

        return claims

    except jwt.ExpiredSignatureError:
        raise errors.unauthorized.InvalidCredentials("ID token has expired")
    except jwt.InvalidTokenError as e:
        log.error(f"Failed to validate ID token: {e}")
        raise errors.unauthorized.InvalidCredentials("Invalid ID token")


def extract_user_info(
    provider: OIDCProvider,
    claims: Dict[str, Any],
) -> OIDCUserInfo:
    """Extract user information from ID token claims"""
    claim_mappings = provider.claims

    subject = claims.get("sub", "")
    username = claims.get(claim_mappings.get("username", "preferred_username"), "")
    email = claims.get(claim_mappings.get("email", "email"))
    name = claims.get(claim_mappings.get("name", "name"))
    given_name = claims.get("given_name")
    family_name = claims.get("family_name")

    # Fallback: use email as username if preferred_username is not available
    if not username and email:
        username = email.split("@")[0]

    # Fallback: use subject as username if nothing else is available
    if not username:
        username = subject

    return OIDCUserInfo(
        subject=subject,
        username=username,
        email=email,
        name=name,
        given_name=given_name,
        family_name=family_name,
    )


def get_or_create_user(
    provider: OIDCProvider,
    user_info: OIDCUserInfo,
) -> AuthUser:
    """
    Get an existing user or create a new one based on OIDC user info.
    Users are matched by email first, then by a generated OIDC user ID.
    Creates entries in both auth.user (for authentication) and backend.user (for user data).
    """
    oidc_config = get_oidc_config()
    default_company = oidc_config.get("default_company", "")
    default_role = oidc_config.get("default_role", "user")

    # Generate a unique user ID based on provider and subject
    oidc_user_id = f"oidc_{provider.name}_{hashlib.sha256(user_info.subject.encode()).hexdigest()[:16]}"

    with translate_errors_context():
        # First, try to find user by email in auth collection
        auth_user = None
        if user_info.email:
            auth_user = AuthUser.objects(email=user_info.email).first()

        # If not found by email, try to find by OIDC user ID
        if not auth_user:
            auth_user = AuthUser.objects(id=oidc_user_id).first()

        if auth_user:
            # Update user info if changed
            updated = False
            if user_info.name and auth_user.name != user_info.name:
                auth_user.name = user_info.name
                updated = True
            if user_info.email and auth_user.email != user_info.email:
                auth_user.email = user_info.email
                updated = True

            if updated:
                auth_user.validated = datetime.utcnow()
                auth_user.save()
                log.info(f"Updated OIDC user: {auth_user.id}")

            # Ensure backend user exists (in case it was deleted or missing)
            _ensure_backend_user(auth_user.id, user_info, default_company or auth_user.company)

            return auth_user

        # Verify company exists
        if not default_company:
            company = Company.objects().first()
            if company:
                default_company = company.id
            else:
                raise errors.server_error.GeneralError(
                    "No default company configured for OIDC users"
                )

        if not Company.objects(id=default_company).first():
            raise errors.server_error.GeneralError(
                f"Invalid default company for OIDC: {default_company}"
            )

        # Map role string to Role enum
        role_map = {
            "user": Role.user,
            "admin": Role.admin,
            "guest": Role.guest,
            "annotator": Role.annotator,
        }
        role = role_map.get(default_role, Role.user)

        # Create new auth user
        # Note: autocreated=False ensures OIDC users persist across server restarts
        # even when fixed_users mode is enabled (which deletes autocreated users not in config)
        auth_user = AuthUser(
            id=oidc_user_id,
            name=user_info.name or user_info.username,
            company=default_company,
            role=role,
            email=user_info.email,
            created=datetime.utcnow(),
            validated=datetime.utcnow(),
            autocreated=False,
        )
        auth_user.save()

        log.info(f"Created new OIDC auth user: {auth_user.id} ({user_info.username})")

        # Create initial credentials for the user
        cred = Credentials(
            key=get_client_id(),
            secret=get_secret_key(),
            label="OIDC auto-generated",
        )
        auth_user.credentials.append(cred)
        auth_user.save()

        # Create backend user (for user preferences and data)
        _ensure_backend_user(oidc_user_id, user_info, default_company)

        return auth_user


def _ensure_backend_user(user_id: str, user_info: OIDCUserInfo, company: str) -> None:
    """
    Ensure a user exists in the backend.user collection.
    This is needed because ClearML uses two collections:
    - auth.user: for authentication (credentials, roles)
    - backend.user: for user data (preferences, display info)
    """
    # Check if backend user already exists
    backend_user = BackendUser.objects(id=user_id).first()
    if backend_user:
        # Update name if changed
        if user_info.name and backend_user.name != user_info.name:
            backend_user.name = user_info.name
            if user_info.given_name:
                backend_user.given_name = user_info.given_name
            if user_info.family_name:
                backend_user.family_name = user_info.family_name
            backend_user.save()
            log.info(f"Updated OIDC backend user: {user_id}")
        return

    # Create new backend user
    display_name = user_info.name or user_info.username
    given_name = user_info.given_name or display_name.split()[0] if display_name else ""
    family_name = user_info.family_name or (display_name.split()[-1] if len(display_name.split()) > 1 else "")

    backend_user = BackendUser(
        id=user_id,
        company=company,
        name=display_name,
        given_name=given_name,
        family_name=family_name,
        created=datetime.utcnow(),
    )
    backend_user.save()
    log.info(f"Created new OIDC backend user: {user_id}")
