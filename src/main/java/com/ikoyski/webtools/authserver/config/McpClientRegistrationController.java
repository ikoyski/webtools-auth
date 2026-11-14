package com.ikoyski.webtools.authserver.config;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Narrow RFC 7591 registration endpoint for remote MCP clients.
 *
 * Registration is disabled by default and is enabled only in the Render test profile.
 * Public clients must use Authorization Code + PKCE and one of the exact callback URIs
 * owned by Grok or Cursor. No client secrets or arbitrary redirect URIs are accepted.
 */
@RestController
public class McpClientRegistrationController {

    private static final Set<String> ALLOWED_REDIRECT_URIS = Set.of(
            "https://grok.com/connectors-oauth-exchange-code/",
            "https://www.cursor.com/agents/mcp/oauth/callback",
            "http://localhost:8787/callback");
    private static final Set<String> ALLOWED_GRANT_TYPES = Set.of("authorization_code", "refresh_token");
    private static final Set<String> ALLOWED_SCOPES = Set.of("kanban.read", "kanban.write", "offline_access");

    private final RegisteredClientRepository clients;
    private final boolean enabled;
    private final String issuer;
    private final String mcpResource;
    private final String mcpBackendResource;

    public McpClientRegistrationController(
            RegisteredClientRepository clients,
            @Value("${auth.mcp.client-registration.enabled:false}") boolean enabled,
            @Value("${auth.issuer}") String issuer,
            @Value("${auth.client.mcp.resource:}") String mcpResource,
            @Value("${auth.client.mcp.backend-resource:${auth.client.web.resource-uri:}}") String mcpBackendResource) {
        this.clients = clients;
        this.enabled = enabled;
        this.issuer = issuer;
        this.mcpResource = mcpResource == null ? "" : mcpResource.trim();
        this.mcpBackendResource = mcpBackendResource == null ? "" : mcpBackendResource.trim();
    }

    @PostMapping(path = "/oauth2/register", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, Object> request) {
        if (!enabled) {
            return ResponseEntity.notFound().build();
        }
        if (mcpResource.isBlank() || mcpBackendResource.isBlank()) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "server_error",
                    "MCP resource audiences are not configured");
        }

        try {
            return createClient(request);
        } catch (IllegalArgumentException ex) {
            return error(HttpStatus.BAD_REQUEST, "invalid_client_metadata", ex.getMessage());
        }
    }

    private ResponseEntity<Map<String, Object>> createClient(Map<String, Object> request) {
        if (request == null) {
            throw new IllegalArgumentException("A JSON client registration request is required");
        }
        if (request.containsKey("client_secret")) {
            throw new IllegalArgumentException("Only public MCP clients are supported");
        }

        List<String> redirectUris = stringList(request.get("redirect_uris"), "redirect_uris", List.of());
        if (redirectUris.isEmpty() || redirectUris.size() > ALLOWED_REDIRECT_URIS.size()
                || new LinkedHashSet<>(redirectUris).size() != redirectUris.size()
                || !ALLOWED_REDIRECT_URIS.containsAll(redirectUris)) {
            throw new IllegalArgumentException("redirect_uris must contain only the approved Grok or Cursor callback URLs");
        }

        List<String> grantTypes = stringList(request.get("grant_types"), "grant_types",
                List.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()));
        Set<String> grantTypeSet = new LinkedHashSet<>(grantTypes);
        if (!grantTypeSet.contains(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                || !ALLOWED_GRANT_TYPES.containsAll(grantTypeSet)) {
            throw new IllegalArgumentException("Only authorization_code and optional refresh_token grants are supported");
        }

        List<String> responseTypes = stringList(request.get("response_types"), "response_types", List.of("code"));
        if (!Set.of("code").equals(new LinkedHashSet<>(responseTypes))) {
            throw new IllegalArgumentException("Only the code response type is supported");
        }

        String authenticationMethod = optionalString(request.get("token_endpoint_auth_method"), "none");
        if (!"none".equals(authenticationMethod)) {
            throw new IllegalArgumentException("MCP clients must use the public token_endpoint_auth_method 'none'");
        }

        String clientName = optionalString(request.get("client_name"), "MCP client").trim();
        if (clientName.isBlank() || clientName.length() > 100) {
            throw new IllegalArgumentException("client_name must contain between 1 and 100 characters");
        }

        String scopeValue = optionalString(request.get("scope"), "kanban.read kanban.write").trim();
        Set<String> scopes = new LinkedHashSet<>();
        for (String scope : scopeValue.split("\\s+")) {
            if (!scope.isBlank()) {
                if (!ALLOWED_SCOPES.contains(scope)) {
                    throw new IllegalArgumentException("Requested scope is not available to MCP clients: " + scope);
                }
                scopes.add(scope);
            }
        }
        if (!scopes.contains("kanban.read")) {
            throw new IllegalArgumentException("The kanban.read scope is required");
        }
        if (scopes.contains("offline_access") && !grantTypeSet.contains(AuthorizationGrantType.REFRESH_TOKEN.getValue())) {
            throw new IllegalArgumentException("offline_access requires the refresh_token grant");
        }

        String clientId = UUID.randomUUID().toString();
        Instant issuedAt = Instant.now();

        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientIdIssuedAt(issuedAt)
                .clientName(clientName)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(true)
                        .setting(ClientSeeder.MCP_RESOURCE_SETTING, mcpResource)
                        .setting(ClientSeeder.MCP_BACKEND_RESOURCE_SETTING, mcpBackendResource)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .reuseRefreshTokens(false)
                        .build());

        if (grantTypeSet.contains(AuthorizationGrantType.REFRESH_TOKEN.getValue())) {
            builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        }
        redirectUris.forEach(builder::redirectUri);
        scopes.forEach(builder::scope);

        clients.save(builder.build());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("client_id", clientId);
        response.put("client_id_issued_at", issuedAt.getEpochSecond());
        response.put("client_name", clientName);
        response.put("redirect_uris", redirectUris);
        response.put("grant_types", new ArrayList<>(grantTypeSet));
        response.put("response_types", List.of("code"));
        response.put("token_endpoint_auth_method", "none");
        response.put("scope", String.join(" ", scopes));

        return ResponseEntity.status(HttpStatus.CREATED)
                .cacheControl(CacheControl.noStore())
                .body(response);
    }

    private static List<String> stringList(Object value, String field, List<String> defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        if (!(value instanceof List<?> values)) {
            throw new IllegalArgumentException(field + " must be an array of strings");
        }
        List<String> result = new ArrayList<>();
        for (Object item : values) {
            if (!(item instanceof String string) || string.isBlank()) {
                throw new IllegalArgumentException(field + " must contain only non-empty strings");
            }
            result.add(string.trim());
        }
        return result;
    }

    private static String optionalString(Object value, String defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        if (!(value instanceof String string)) {
            throw new IllegalArgumentException("Client registration string fields must be strings");
        }
        return string;
    }

    private static ResponseEntity<Map<String, Object>> error(
            HttpStatus status, String error, String description) {
        return ResponseEntity.status(status)
                .cacheControl(CacheControl.noStore())
                .body(Map.of("error", error, "error_description", description));
    }
}
