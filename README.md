# WebTools Identity Server

Spring Authorization Server built with Spring Boot 3.4.2 and Java 21. It is the shared identity provider for first-party Webtools applications and registered integrations. It authenticates people through configured identity providers (currently Google and GitHub), maintains a central person record, and issues OAuth 2.0 / OpenID Connect tokens to separate clients.

The identity server owns platform-wide identities and linked provider subjects in its own database. It does not own application data or application roles. Each resource server provisions its own local profile against the stable central identity ID and makes its own authorization decisions.

## Sign-in and token flow

1. An OAuth client redirects the browser to `/oauth2/authorize` using Authorization Code and PKCE (`S256`).
2. If there is no authorization-server session, the user is sent to the branded `/login` page, where they choose a configured identity provider.
3. The provider returns to the Spring Security OAuth2 login callback.
4. `FederatedLoginSuccessHandler` normalizes the provider identity and resolves or creates a central identity in the Auth Server's own database.
5. The authorization server establishes the central UUID as the authenticated principal and completes authorization.
6. The client exchanges the authorization code at `/oauth2/token` for a signed JWT access token and, when `openid` was requested, an OIDC ID token.
7. Each resource server validates issuer, signature, audience and its application scopes, then provisions/loads its own local user profile and applies application-specific permissions.

## Onboarding another Webtools application

See [Application onboarding](docs/application-onboarding.md) for client registration, redirect URIs, API audiences, scopes, CORS, logout allow-lists, Gateway routes and local user provisioning.

## Branded login page

The authorization server serves its provider-selection UI from `src/main/resources/static/login.html`. Requests to `/login` are routed by `LoginPageController` to that static page. Its Google and GitHub buttons use Spring Security's standard `/oauth2/authorization/{registrationId}` endpoints.

The page is presentation only. Provider registration, callback URLs, verified-identity handling, central identity resolution, OAuth authorization and token issuance remain server-side.

The same login session is shared across registered clients at this issuer (SSO). The identity server authenticates people; it does not grant Kanban board roles, Ipon permissions or other application permissions. Resource servers remain responsible for their own authorization. OIDC clients request `openid`; `profile` and/or `email` are requested only when those claims are needed. ID tokens contain only claims covered by the granted standard scopes; the default UserInfo endpoint derives its claims from the ID token.

## Token claims and keys

The stable central identity UUID is the token subject (`sub`) and is also emitted as the legacy `uid` claim so the current gateway can migrate without breaking. Tokens include `email` and, when available, `name` and `picture`. OIDC ID tokens include standard `email`, `email_verified`, `name` and `picture` claims for the requested scopes.

Each first-party application client can be assigned its own API resource URI. That URI is emitted as the access token `aud`; ordinary browser clients receive only their own API audience. Kanban MCP clients receive both the MCP resource URI and the backing Kanban API resource URI because the MCP service forwards the user's delegated token to that API. Configure exact audiences for every resource server and reject tokens that do not include the intended resource.

JWTs are signed asymmetrically. Resource servers validate signatures using the public keys published at:

```text
https://auth.ikoyski.top/oauth2/jwks
```

The issuer is:

```text
https://auth.ikoyski.top
```

Keep the issuer stable and consistent with gateway and MCP JWT validation configuration. Persist the signing key across restarts; an ephemeral key invalidates previously issued tokens after restart.

## Registered OAuth clients

Pre-registered clients are seeded/upserted by `ClientSeeder` at application startup from Config Server properties. Homelab MCP has stable provider-specific client IDs: `homelab-claude`, `homelab-gemini`, and `homelab-grok`. Kanban's Grok and Cursor integrations can still use the restricted DCR endpoint described below. Do not edit `oauth2_registered_client` manually.

| Client | Purpose | Typical security model |
|---|---|---|
| Claude | MCP access | Configurable public or confidential client; PKCE |
| Homelab Claude | Homelab MCP | `homelab-claude`; public PKCE client |
| Homelab Gemini | Homelab MCP | `homelab-gemini`; public PKCE client; validated dynamic callback |
| Homelab Grok | Homelab MCP | Pre-registered public client (`homelab-grok`); PKCE; no client secret |
| ChatGPT | MCP access | Optional; PKCE; public without a secret, confidential with a secret |
| Gemini | MCP access | Optional; PKCE; public without a secret, confidential with a secret |
| Grok | MCP access | Restricted DCR; generated confidential-client secret; PKCE; exact callback allow-list |
| Cursor | MCP access | Dynamic public client registration; PKCE; exact web/desktop callback allow-list |
| Kanban web | Browser application | Public OIDC client with PKCE |
| Additional first-party apps | Configured browser applications | One public OIDC client per app, PKCE and app-specific API audience |

Kanban MCP clients use `auth.resources.kanban-mcp.resource` and also receive the backing Kanban API resource URI in `aud`, because the Kanban MCP service forwards the delegated token to that API. Homelab MCP clients use only `auth.resources.homelab-mcp.resource`; they never receive the Kanban backend audience. The Kanban web client itself receives only its API audience. Additional first-party browser clients are configured under `auth.clients.applications`; each requires its own exact redirect URI list, scopes and API `resource-uri`.

Optional ChatGPT is seeded only when its client ID and at least one redirect URI are configured. The named Homelab Claude and Gemini clients are seeded with defaults `homelab-claude` and `homelab-gemini`; Gemini's redirect-uris list is empty because Google supplies a user-bound callback at authorization time. The named Homelab Grok client defaults to `homelab-grok` and is seeded from its client ID and exact redirect URI list; it is a public client using `ClientAuthenticationMethod.NONE`, PKCE and no client secret. All named Homelab MCP clients require PKCE and have one-hour access tokens with no refresh-token grant. The Kanban browser client retains its separately configured eight-hour access-token lifetime.

### Redirect URI rules

- Register exact redirect URIs supplied by the OAuth client product. Never use wildcards.
- For ChatGPT, use the exact callback URL shown in the connector setup UI. Depending on the integration flow, this may be a callback-specific URL rather than the stable `/connector_platform_oauth_redirect` URI. The server's authorization-response issuer-identification behavior must also match the callback requirements.
- Gemini MCP uses a per-user callback under `https://oauth-redirect.googleusercontent.com/r/`. The auth server validates HTTPS, the exact Google redirect host and the user-bound callback path shape; no per-user callback is stored in Config Server. Current code computes the expected resource-host slug but does not compare that slug with the callback path suffix, so do not claim that the suffix is cryptographically/resource-specifically bound until the validator and its tests are corrected. The client seeder stores a reserved placeholder URI because Spring requires a redirect URI on authorization-code client registrations; the Gemini validator never accepts that placeholder.
- The Kanban Grok DCR flow uses the observed callback `https://grok.com/connectors-oauth-exchange-code/`. This is distinct from the pre-registered Homelab client `homelab-grok`, which is a public PKCE client and does not use DCR.
- Cursor remote MCP uses DCR with the documented web callback `https://www.cursor.com/agents/mcp/oauth/callback` and desktop callback `http://localhost:8787/callback`.
- DCR is exposed at `/oauth2/register` and advertised in authorization-server metadata only when `auth.mcp.client-registration.enabled=true`. It remains disabled by default in application code. The current base Config Server file `config/webtools-auth.yaml` explicitly sets it to `true`. The current `config-public/webtools-auth-public.yaml` overlay does not override that setting; there is no committed `webtools-auth-mcp.yaml` overlay. Therefore the base setting is inherited by the public profile unless a later profile-specific override is added. Review this carefully before deployment; DCR should be enabled only where the integration is intentionally being tested.
- DCR accepts only Authorization Code clients with PKCE, approved callbacks, and one application-specific scope family per client. Refresh-token grants and the `offline_access` scope are not supported for MCP clients. Kanban clients may request `kanban.read`/`kanban.write` and receive the Kanban MCP plus backing API audiences. Homelab clients may request `homelab.read` and receive only the Homelab MCP audience; mixed Kanban/Homelab scopes are rejected. Claude and Gemini callbacks are accepted alongside the existing Grok and Cursor callbacks. Cursor and Claude use public clients (`none`). DCR Grok clients may use `client_secret_post` with the exact Grok callback; the server generates a high-entropy secret, stores only its password-encoded form and returns the secret once. Caller-supplied secrets, arbitrary redirects, unrelated scopes, refresh-token grants, `offline_access`, and arbitrary resource audiences are rejected. The named Homelab clients are pre-registered separately and do not depend on DCR.
- Test the complete authorization-code flow with each product before enabling it for users.

## Named Homelab MCP OAuth clients

```yaml
auth:
  resources:
    homelab-mcp:
      resource: https://homelab-mcp.ikoyski.top/mcp
  clients:
    homelab-claude:
      client-id: homelab-claude
      resource: homelab-mcp
      redirect-uris:
        - https://claude.ai/api/mcp/auth_callback
        - https://claude.com/api/mcp/auth_callback
    homelab-gemini:
      client-id: homelab-gemini
      resource: homelab-mcp
      redirect-uris: []
    homelab-grok:
      client-id: homelab-grok
      resource: homelab-mcp
      # Public PKCE client; no client secret.
      redirect-uris:
        - https://grok.com/connectors-oauth-exchange-code/
```

The named `homelab-grok` client is public and does not require `AUTH_HOMELAB_GROK_CLIENT_SECRET`. Do not add a secret to this named client. The separate DCR-created Grok client may use the generated `client_secret_post` secret returned once by the registration endpoint. Claude, Gemini and the named Homelab Grok client are public PKCE clients. Gemini's registered placeholder is an internal Spring Authorization Server requirement; it is not an accepted live callback.

### Homelab named-client behavior

The three pre-registered Homelab clients are separate from the Kanban MCP clients and from random client IDs created through DCR:

| Client ID | Client type | Callback behavior | Scope / audience |
|---|---|---|---|
| `homelab-claude` | Public PKCE | Exact Claude callback allow-list | `homelab.read`; Homelab MCP resource only |
| `homelab-gemini` | Public PKCE | Google user-bound callback validated by the Auth Server | `homelab.read`; Homelab MCP resource only |
| `homelab-grok` | Public PKCE | Exact Grok callback in its named registration | `homelab.read`; Homelab MCP resource only |

These named clients are seeded by `ClientSeeder` when the Homelab resource and required client registration values are present. They do not need DCR and do not receive the Kanban backend audience. The named `homelab-grok` client has no client secret. A DCR-created Grok client is a separate flow and may be confidential using a server-generated secret.

## Config Server properties

The identity server expects its issuer, database, federated-provider credentials, signing-key paths and OAuth client registrations to be supplied through external configuration. MCP Dynamic Client Registration is controlled by `auth.mcp.client-registration.enabled` and defaults to disabled in application code. The homelab's private/base configuration explicitly enables it for controlled Grok integration testing; Render test uses its separate `webtools-auth-mcp.yaml` overlay. Keep it disabled in environments where Grok/Cursor onboarding is not being tested.

For GitHub sign-in, the Config Server provides the `spring.security.oauth2.client.registration.github` properties (`client-id`, `client-secret`, and scopes `read:user`, `user:email`). Keep the OAuth App secret in the private configuration/secret store, not in the frontend repository.

Representative MCP client configuration:

```yaml
auth:
  issuer: https://auth.ikoyski.top
  mcp:
    # Enable only in a controlled integration-test environment.
    client-registration:
      enabled: true
  resources:
    kanban-mcp:
      resource: https://api.ikoyski.top/kanban-mcp/mcp
      backend-resource: https://api.ikoyski.top/kanban-backend
    homelab-mcp:
      resource: https://homelab-mcp.ikoyski.top/mcp
  clients:
    kanban-web:
      client-id: kanban-web
      resource: https://api.ikoyski.top/kanban-backend
      redirect-uris:
        - https://pages.ikoyski.top/kanban/kanban.html
      access-token-ttl: ${AUTH_WEB_ACCESS_TOKEN_TTL:PT8H}
    kanban-claude:
      client-id: kanban-claude
      resource: kanban-mcp
      client-secret: ${AUTH_CLAUDE_CLIENT_SECRET:}
      redirect-uris:
        - https://claude.ai/api/mcp/auth_callback
    kanban-chatgpt:
      client-id: kanban-chatgpt
      resource: kanban-mcp
      client-secret: ${AUTH_CHATGPT_CLIENT_SECRET:}
      redirect-uris:
        - https://chatgpt.com/connector_platform_oauth_redirect
    kanban-gemini:
      client-id: kanban-gemini
      resource: kanban-mcp
      client-secret: ${AUTH_GEMINI_CLIENT_SECRET:}
      redirect-uris: [] # Gemini supplies a per-user callback; validated by the auth server
    homelab-claude:
      client-id: homelab-claude
      resource: homelab-mcp
      redirect-uris:
        - https://claude.ai/api/mcp/auth_callback
        - https://claude.com/api/mcp/auth_callback
    homelab-gemini:
      client-id: homelab-gemini
      resource: homelab-mcp
      redirect-uris: []
    homelab-grok:
      client-id: homelab-grok
      resource: homelab-mcp
      client-secret: ${AUTH_HOMELAB_GROK_CLIENT_SECRET:}
      redirect-uris:
        - https://grok.com/connectors-oauth-exchange-code/
    applications:
      - client-id: ipon-web
        name: Ipon web
        redirect-uris:
          - https://ipon.example.com/oauth/callback
        scopes: [openid, profile, email, ipon.read, ipon.write]
        resource-uri: https://api.example.com/ipon
```

The MCP resource URI must match the audience expected by the MCP resource server and the gateway's protected-resource configuration. It is a configured resource binding; the current implementation does not dynamically validate arbitrary RFC 8707 `resource` request parameters. Do not describe this as full dynamic RFC 8707 resource-indicator support.

Secrets and environment-specific values belong in the private Config Server/secret store or deployment environment, not in application source.

## Google identity provider setup

For Google sign-in, configure a Web application OAuth client and register the exact Spring Security callback:

```text
https://auth.ikoyski.top/login/oauth2/code/google
```

Configure the required OpenID Connect scopes (`openid`, `email`, `profile`) and publish/authorize the consent configuration for the intended users. Use a dedicated provider client for this server.

## GitHub identity provider setup

Create a GitHub OAuth App and configure its callback URL as:

```text
https://auth.ikoyski.top/login/oauth2/code/github
```

The Config Server registration uses the GitHub OAuth App's client ID and client secret with the `read:user` and `user:email` scopes. Spring Security loads the GitHub profile, and `GitHubOAuth2UserService` calls `GET https://api.github.com/user/emails` to select the primary email only when GitHub marks it as verified. The numeric GitHub account ID is the stable identity subject; the mutable GitHub login name and email are not used as identifiers.

The auth server must have the exact callback URL registered in the GitHub OAuth App. Do not request repository scopes: Kanban sign-in only needs the user's profile and verified email address.

## Signing key setup

Generate and securely store an RSA key pair using an approved secret-management process. The private key must never be committed to Git. Configure the application with persistent private/public key file paths. Ensure the public key exposed through JWKS corresponds to the private signing key.

## Run and verify

Requirements: JDK 21, Maven, reachable PostgreSQL database, Config Server configuration, identity-provider credentials and persistent signing keys.

```bash
./mvnw clean verify
./mvnw spring-boot:run
```

Inspect the published metadata and keys:

```bash
curl -s https://auth.ikoyski.top/.well-known/oauth-authorization-server
curl -s https://auth.ikoyski.top/oauth2/jwks
```

Verify the issuer, authorization-code grant, PKCE `S256`, token endpoint and signing key set. Then test a complete login and code exchange for every registered client.

## Deployment and operational notes

The service is deployed separately from the API gateway. Restrict and rate-limit public authentication endpoints such as `/oauth2/token` and login routes at the edge. Ensure the database, signing keys and authorization-server session configuration survive normal restarts.

## Development rules

- Keep this database as the source of truth for platform identity and provider-subject links.
- Never silently link two provider accounts by email; add account linking only as an explicit authenticated flow.
- Keep application profiles, memberships, roles and permissions in each application's own resource server.
- Never log access tokens, client secrets, private keys or backend internal credentials.
- Keep redirect URI matching exact for all clients except the narrowly validated Gemini user-bound callback. Never introduce wildcard matching.
- Preserve PKCE for public and confidential authorization-code clients.
- Ensure each resource client receives only its configured audience; never reuse one application's audience for another.
- Require exact audience and application-specific scopes at every resource server.
- Keep OIDC enabled and retain the stable central UUID as the subject.
- Keep client seeding idempotent and config-driven.
- Keep open MCP Dynamic Client Registration disabled by default in application code. When explicitly enabled for testing, enforce the exact Grok/Cursor callback allow-list, PKCE, Kanban-only scopes and both MCP/backend audiences; only Grok's exact callback may use server-generated `client_secret_post` credentials.
- Keep CORS allowed origins and logout redirect URLs as explicit lists; add each first-party app's exact origin and signed-out landing URL when onboarding it.
- For OIDC, include `openid`; request standard `profile` / `email` scopes only when needed and validate ID tokens in the client.
- Update README and `CLAUDE.md` when client registration, claims, login, key management or deployment behavior changes.
- Run `./mvnw clean verify`; do not claim live provider flows were tested unless they were actually executed.

## Related components

- `webtools-config-server` — externalized application configuration.
- `webtools-api-gateway` — public routing and gateway-side token/resource protection.
- `webtools-kanban-mcp` — MCP resource server that validates the issued JWT and forwards it to the Kanban API.
- `webtools-kanban` — Kanban frontend and user experience.
