package com.ikoyski.webtools.authserver.config;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
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
 * Cursor uses public Authorization Code + PKCE. Grok's observed DCR request uses
 * client_secret_post, so Grok receives a generated confidential-client secret. Both
 * clients remain restricted to approved callback URIs and one application-specific resource audience.
 */
@RestController
public class McpClientRegistrationController {

    private static final Logger log = LoggerFactory.getLogger(McpClientRegistrationController.class);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final String GROK_REDIRECT_URI = "https://grok.com/connectors-oauth-exchange-code/";
    private static final Set<String> ALLOWED_REDIRECT_URIS = Set.of(
            GROK_REDIRECT_URI,
            "https://claude.ai/api/mcp/auth_callback",
            "https://claude.com/api/mcp/auth_callback",
            "https://www.cursor.com/agents/mcp/oauth/callback",
            "http://localhost:8787/callback");

    /**
     * Claude Code is a native OAuth client. Its loopback callback port is selected at
     * runtime, so only the host and fixed callback path are allow-listed here.
     * This exception is intentionally limited to Homelab MCP DCR clients below.
     */
    static boolean isClaudeCodeLoopbackRedirectUri(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        try {
            java.net.URI uri = new java.net.URI(value);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            int port = uri.getPort();
            return scheme != null
                    && "http".equalsIgnoreCase(scheme)
                    && host != null
                    && ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host))
                    && port >= 1 && port <= 65535
                    && "/callback".equals(uri.getRawPath())
                    && uri.getRawUserInfo() == null
                    && uri.getRawQuery() == null
                    && uri.getRawFragment() == null;
        } catch (java.net.URISyntaxException ex) {
            return false;
        }
    }
    private static final Set<String> ALLOWED_GRANT_TYPES = Set.of("authorization_code", "refresh_token");
    private static final Duration MCP_REFRESH_TOKEN_TTL = Duration.ofDays(30);
    private static final Set<String> KANBAN_SCOPES = Set.of("kanban.read", "kanban.write");
    private static final Set<String> HOMELAB_SCOPES = Set.of("homelab.read");

    private final RegisteredClientRepository clients;
    private final PasswordEncoder passwordEncoder;
    private final boolean enabled;
    private final String mcpResource;
    private final String mcpBackendResource;
    private final String homelabMcpResource;

    public McpClientRegistrationController(
            RegisteredClientRepository clients,
            PasswordEncoder passwordEncoder,
            @Value("${auth.mcp.client-registration.enabled:false}") boolean enabled,
            @Value("${auth.resources.kanban-mcp.resource:}") String mcpResource,
            @Value("${auth.resources.kanban-mcp.backend-resource:}") String mcpBackendResource,
            @Value("${auth.resources.homelab-mcp.resource:}") String homelabMcpResource) {
        this.clients = clients;
        this.passwordEncoder = passwordEncoder;
        this.enabled = enabled;
        this.mcpResource = mcpResource == null ? "" : mcpResource.trim();
        this.mcpBackendResource = mcpBackendResource == null ? "" : mcpBackendResource.trim();
        this.homelabMcpResource = homelabMcpResource == null ? "" : homelabMcpResource.trim();
    }

    @PostMapping(path = "/oauth2/register", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, Object> request) {
        if (!enabled) {
            return ResponseEntity.notFound().build();
        }
        try {
            return createClient(request);
        } catch (IllegalArgumentException ex) {
            // Log only fixed diagnostic categories. Never log submitted metadata,
            // client names, redirect URIs, scope values, secrets, or exception messages.
            String reason = rejectionReason(ex.getMessage());
            if ("unsupported_token_endpoint_auth_method".equals(reason)) {
                Object submittedMethod = request == null ? null : request.get("token_endpoint_auth_method");
                log.warn("mcp_client_registration_rejected reason={} auth_method_category={}",
                        reason, authenticationMethodCategory(submittedMethod));
            } else if ("unsupported_grant_types".equals(reason)) {
                Object submittedGrantTypes = request == null ? null : request.get("grant_types");
                log.warn("mcp_client_registration_rejected reason={} grant_type_categories={}",
                        reason, grantTypeCategories(submittedGrantTypes));
            } else {
                log.warn("mcp_client_registration_rejected reason={}", reason);
            }
            return error(HttpStatus.BAD_REQUEST, "invalid_client_metadata", ex.getMessage());
        }
    }

    static String authenticationMethodCategory(Object value) {
        if (value == null) return "omitted";
        if (!(value instanceof String method)) return "invalid_type";
        return switch (method) {
            case "none" -> "none";
            case "client_secret_basic" -> "client_secret_basic";
            case "client_secret_post" -> "client_secret_post";
            case "client_secret_jwt" -> "client_secret_jwt";
            case "private_key_jwt" -> "private_key_jwt";
            case "tls_client_auth" -> "tls_client_auth";
            case "self_signed_tls_client_auth" -> "self_signed_tls_client_auth";
            default -> "other";
        };
    }

    static List<String> grantTypeCategories(Object value) {
        if (value == null) return List.of("omitted");
        if (!(value instanceof List<?> grantTypes)) return List.of("invalid_type");

        Set<String> categories = new LinkedHashSet<>();
        for (Object grantType : grantTypes) {
            if (!(grantType instanceof String type) || type.isBlank()) {
                categories.add("invalid_item");
                continue;
            }
            categories.add(switch (type.trim()) {
                case "authorization_code" -> "authorization_code";
                case "refresh_token" -> "refresh_token";
                case "client_credentials" -> "client_credentials";
                case "password" -> "password";
                case "implicit" -> "implicit";
                case "urn:ietf:params:oauth:grant-type:device_code" -> "device_code";
                case "urn:ietf:params:oauth:grant-type:token-exchange" -> "token_exchange";
                default -> "other";
            });
        }
        return List.copyOf(categories);
    }

    private static String rejectionReason(String message) {
        if (message == null) return "invalid_metadata";
        if (message.contains("JSON client registration request")) return "missing_request";
        if (message.contains("public MCP clients")) return "client_secret_not_allowed";
        if (message.startsWith("redirect_uris")) return "invalid_redirect_uris";
        if (message.contains("grant")) return "unsupported_grant_types";
        if (message.contains("response type")) return "unsupported_response_types";
        if (message.contains("token_endpoint_auth_method")) return "unsupported_token_endpoint_auth_method";
        if (message.startsWith("client_name")) return "invalid_client_name";
        if (message.startsWith("Requested scope")) return "unsupported_scope";
        if (message.contains("kanban.read")) return "required_scope_missing";
        if (message.contains("Client registration string fields")) return "invalid_string_field_type";
        if (message.contains("must be an array of strings")) return "invalid_array_field";
        if (message.contains("must contain only non-empty strings")) return "invalid_array_item";
        return "invalid_metadata";
    }

    private ResponseEntity<Map<String, Object>> createClient(Map<String, Object> request) {
        if (request == null) {
            throw new IllegalArgumentException("A JSON client registration request is required");
        }
        if (request.containsKey("client_secret")) {
            throw new IllegalArgumentException("Client secrets must be generated by the authorization server");
        }

        List<String> redirectUris = stringList(request.get("redirect_uris"), "redirect_uris", List.of());
        boolean geminiDynamicRedirect = redirectUris.size() == 1
                && GeminiRedirectUriValidator.isValidRedirectUri(
                        redirectUris.get(0), GeminiRedirectUriValidator.resourceHostSlug(homelabMcpResource));
        boolean claudeCodeLoopbackRedirect = redirectUris.size() == 1
                && isClaudeCodeLoopbackRedirectUri(redirectUris.get(0));
        boolean containsClaudeCodeLoopbackRedirect = redirectUris.stream()
                .anyMatch(McpClientRegistrationController::isClaudeCodeLoopbackRedirectUri);
        if (redirectUris.isEmpty() || redirectUris.size() > 2
                || new LinkedHashSet<>(redirectUris).size() != redirectUris.size()
                || (containsClaudeCodeLoopbackRedirect && !claudeCodeLoopbackRedirect)
                || (!ALLOWED_REDIRECT_URIS.containsAll(redirectUris)
                        && !geminiDynamicRedirect && !claudeCodeLoopbackRedirect)) {
            throw new IllegalArgumentException("redirect_uris must contain only approved Claude, Grok, Cursor, Gemini or Claude Code callback URLs");
        }

        List<String> grantTypes = stringList(request.get("grant_types"), "grant_types",
                List.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()));
        Set<String> grantTypeSet = new LinkedHashSet<>(grantTypes);
        if (!grantTypeSet.contains(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                || !ALLOWED_GRANT_TYPES.containsAll(grantTypeSet)) {
            throw new IllegalArgumentException("Only authorization_code, optionally combined with refresh_token, is supported");
        }
        // Claude Code requests refresh_token as part of its native OAuth client registration.
        // The global allowlist above keeps this to authorization_code and refresh_token only.
        // Its public-client, PKCE, Homelab-only scope and audience restrictions remain enforced.

        List<String> responseTypes = stringList(request.get("response_types"), "response_types", List.of("code"));
        if (!Set.of("code").equals(new LinkedHashSet<>(responseTypes))) {
            throw new IllegalArgumentException("Only the code response type is supported");
        }

        String authenticationMethod = optionalString(request.get("token_endpoint_auth_method"), "none");
        boolean confidentialGrokClient = "client_secret_post".equals(authenticationMethod);
        if (!"none".equals(authenticationMethod) && !confidentialGrokClient) {
            throw new IllegalArgumentException("MCP clients must use 'none' or the approved Grok 'client_secret_post' method");
        }
        if (confidentialGrokClient && !redirectUris.equals(List.of(GROK_REDIRECT_URI))) {
            throw new IllegalArgumentException("client_secret_post is reserved for the exact Grok callback");
        }
        if (claudeCodeLoopbackRedirect && !"none".equals(authenticationMethod)) {
            throw new IllegalArgumentException("Claude Code loopback clients must be public clients using token_endpoint_auth_method 'none'");
        }

        String clientName = optionalString(request.get("client_name"), "MCP client").trim();
        if (!clientName.matches("[A-Za-z0-9 ._()\\-]{1,100}")) {
            throw new IllegalArgumentException("client_name may contain only letters, numbers, spaces and basic punctuation (maximum 100 characters)");
        }

        String scopeValue = optionalString(request.get("scope"),
                claudeCodeLoopbackRedirect ? "homelab.read" : "kanban.read kanban.write").trim();
        Set<String> scopes = new LinkedHashSet<>();
        for (String scope : scopeValue.split("\\s+")) {
            if (!scope.isBlank()) {
                if (!KANBAN_SCOPES.contains(scope) && !HOMELAB_SCOPES.contains(scope)) {
                    throw new IllegalArgumentException("Requested scope is not available to MCP clients: " + scope);
                }
                scopes.add(scope);
            }
        }
        boolean homelabClient = scopes.contains("homelab.read");
        if (homelabClient && scopes.stream().anyMatch(scope -> !HOMELAB_SCOPES.contains(scope))) {
            throw new IllegalArgumentException("Homelab and Kanban scopes cannot be combined in one client");
        }
        if (claudeCodeLoopbackRedirect && (!homelabClient || scopes.size() != 1)) {
            throw new IllegalArgumentException("Claude Code loopback clients are restricted to the homelab.read scope");
        }
        if (!homelabClient && !scopes.contains("kanban.read")) {
            throw new IllegalArgumentException("The kanban.read scope is required");
        }
        if (homelabClient && homelabMcpResource.isBlank()) {
            throw new IllegalArgumentException("The Homelab MCP resource audience is not configured");
        }
        if (!homelabClient && (mcpResource.isBlank() || mcpBackendResource.isBlank())) {
            throw new IllegalArgumentException("Kanban MCP resource audiences are not configured");
        }
                String clientId = UUID.randomUUID().toString();
        Instant issuedAt = Instant.now();
        String clientSecret = confidentialGrokClient ? generateClientSecret() : null;

        ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder()
                .requireProofKey(true)
                .requireAuthorizationConsent(true)
                .setting(ClientSeeder.MCP_RESOURCE_SETTING, homelabClient ? homelabMcpResource : mcpResource);
        if (!homelabClient) {
            // Kanban retains its existing backend audience; Homelab must never inherit it.
            clientSettingsBuilder.setting(ClientSeeder.MCP_BACKEND_RESOURCE_SETTING, mcpBackendResource);
        }
        if (geminiDynamicRedirect) {
            clientSettingsBuilder.setting(ClientSeeder.GEMINI_DYNAMIC_REDIRECT_SETTING, true);
        }

        TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .accessTokenTimeToLive(Duration.ofHours(1));
        if (grantTypeSet.contains(AuthorizationGrantType.REFRESH_TOKEN.getValue())) {
            tokenSettingsBuilder.refreshTokenTimeToLive(MCP_REFRESH_TOKEN_TTL)
                    .reuseRefreshTokens(false);
        }

        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientIdIssuedAt(issuedAt)
                .clientName(clientName)
                .clientAuthenticationMethod(confidentialGrokClient
                        ? ClientAuthenticationMethod.CLIENT_SECRET_POST : ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .clientSettings(clientSettingsBuilder.build())
                .tokenSettings(tokenSettingsBuilder.build());

        if (clientSecret != null) {
            builder.clientSecret(passwordEncoder.encode(clientSecret));
        }
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
        response.put("token_endpoint_auth_method", authenticationMethod);
        response.put("scope", String.join(" ", scopes));
        if (clientSecret != null) {
            // RFC 7591: return the generated secret once; zero means it does not expire.
            response.put("client_secret", clientSecret);
            response.put("client_secret_expires_at", 0);
        }

        return ResponseEntity.status(HttpStatus.CREATED)
                .cacheControl(CacheControl.noStore())
                .body(response);
    }

    private static String generateClientSecret() {
        byte[] secret = new byte[32];
        SECURE_RANDOM.nextBytes(secret);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
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
