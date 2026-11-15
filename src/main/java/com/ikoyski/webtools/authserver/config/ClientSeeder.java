package com.ikoyski.webtools.authserver.config;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

@Component
public class ClientSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(ClientSeeder.class);
    public static final String MCP_RESOURCE_SETTING = "mcp.resource";
    public static final String MCP_BACKEND_RESOURCE_SETTING = "mcp.backend-resource";
    public static final String RESOURCE_URI_SETTING = "resource.uri";
    public static final String GEMINI_DYNAMIC_REDIRECT_SETTING = "gemini.dynamic-redirect-uri";
    private static final String GEMINI_REDIRECT_URI_PLACEHOLDER =
            "https://oauth-redirect.googleusercontent.com/r/__dynamic_callback_placeholder__";

    private final RegisteredClientRepository clients;
    private final PasswordEncoder passwordEncoder;
    private final String claudeClientId;
    private final String claudeClientSecret;
    private final List<String> claudeRedirectUris;
    private final String webClientId;
    private final List<String> webRedirectUris;
    private final Duration webAccessTokenTtl;
    private final String webResourceUri;
    private final ApplicationClientProperties applicationClients;
    private final String mcpResource;
    private final String mcpBackendResource;
    private final String chatgptClientId;
    private final String chatgptClientSecret;
    private final List<String> chatgptRedirectUris;
    private final String geminiClientId;
    private final String geminiClientSecret;
    private final List<String> geminiRedirectUris;
    private final String homelabMcpResource;
    private final String homelabClaudeClientId;
    private final List<String> homelabClaudeRedirectUris;
    private final String homelabGeminiClientId;
    private final List<String> homelabGeminiRedirectUris;
    private final String homelabGrokClientId;
    private final String homelabGrokClientSecret;
    private final List<String> homelabGrokRedirectUris;

    public ClientSeeder(RegisteredClientRepository clients,
                        PasswordEncoder passwordEncoder,
                        @Value("${auth.client.claude.client-id}") String claudeClientId,
                        @Value("${auth.client.claude.client-secret:}") String claudeClientSecret,
                        @Value("${auth.client.claude.redirect-uris}") List<String> claudeRedirectUris,
                        @Value("${auth.client.web.client-id:}") String webClientId,
                        @Value("${auth.client.web.redirect-uris:}") List<String> webRedirectUris,
                        @Value("${auth.client.web.access-token-ttl:PT8H}") Duration webAccessTokenTtl,
                        @Value("${auth.client.web.resource-uri:}") String webResourceUri,
                        ApplicationClientProperties applicationClients,
                        @Value("${auth.client.mcp.resource:}") String mcpResource,
                        @Value("${auth.client.mcp.backend-resource:}") String mcpBackendResource,
                        @Value("${auth.client.chatgpt.client-id:}") String chatgptClientId,
                        @Value("${auth.client.chatgpt.client-secret:}") String chatgptClientSecret,
                        @Value("${auth.client.chatgpt.redirect-uris:}") List<String> chatgptRedirectUris,
                        @Value("${auth.client.gemini.client-id:}") String geminiClientId,
                        @Value("${auth.client.gemini.client-secret:}") String geminiClientSecret,
                        @Value("${auth.client.gemini.redirect-uris:}") List<String> geminiRedirectUris,
                        @Value("${auth.client.homelab-mcp.resource:}") String homelabMcpResource,
                        @Value("${auth.client.homelab-mcp.claude.client-id:homelab-claude}") String homelabClaudeClientId,
                        @Value("${auth.client.homelab-mcp.claude.redirect-uris:https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback}") List<String> homelabClaudeRedirectUris,
                        @Value("${auth.client.homelab-mcp.gemini.client-id:homelab-gemini}") String homelabGeminiClientId,
                        @Value("${auth.client.homelab-mcp.gemini.redirect-uris:}") List<String> homelabGeminiRedirectUris,
                        @Value("${auth.client.homelab-mcp.grok.client-id:homelab-grok}") String homelabGrokClientId,
                        @Value("${auth.client.homelab-mcp.grok.client-secret:${AUTH_HOMELAB_GROK_CLIENT_SECRET:}}") String homelabGrokClientSecret,
                        @Value("${auth.client.homelab-mcp.grok.redirect-uris:https://grok.com/connectors-oauth-exchange-code/}") List<String> homelabGrokRedirectUris) {
        this.clients = clients;
        this.passwordEncoder = passwordEncoder;
        this.claudeClientId = claudeClientId;
        this.claudeClientSecret = claudeClientSecret;
        this.claudeRedirectUris = claudeRedirectUris;
        this.webClientId = webClientId;
        this.webRedirectUris = webRedirectUris;
        this.webAccessTokenTtl = webAccessTokenTtl;
        this.webResourceUri = webResourceUri == null ? "" : webResourceUri.trim();
        this.applicationClients = applicationClients;
        this.mcpResource = mcpResource == null ? "" : mcpResource.trim();
        this.mcpBackendResource = mcpBackendResource == null || mcpBackendResource.isBlank()
                ? this.webResourceUri : mcpBackendResource.trim();
        this.chatgptClientId = chatgptClientId;
        this.chatgptClientSecret = chatgptClientSecret;
        this.chatgptRedirectUris = chatgptRedirectUris;
        this.geminiClientId = geminiClientId;
        this.geminiClientSecret = geminiClientSecret;
        this.geminiRedirectUris = geminiRedirectUris;
        this.homelabMcpResource = homelabMcpResource == null ? "" : homelabMcpResource.trim();
        this.homelabClaudeClientId = homelabClaudeClientId;
        this.homelabClaudeRedirectUris = homelabClaudeRedirectUris;
        this.homelabGeminiClientId = homelabGeminiClientId;
        this.homelabGeminiRedirectUris = homelabGeminiRedirectUris;
        this.homelabGrokClientId = homelabGrokClientId;
        this.homelabGrokClientSecret = homelabGrokClientSecret;
        this.homelabGrokRedirectUris = homelabGrokRedirectUris;
    }

    @Override
    public void run(ApplicationArguments args) {
        seedClaude();
        seedWeb();
        seedConfiguredApplications();
        seedMcpClient(chatgptClientId, chatgptClientSecret, "ChatGPT MCP connector",
                chatgptRedirectUris, false, false);
        // Gemini creates a per-user callback URL. Its exact URL is validated at authorization time.
        seedMcpClient(geminiClientId, geminiClientSecret, "Gemini MCP connector",
                geminiRedirectUris, true, true);
        seedHomelabMcpClients();
    }

    /**
     * Registers stable, provider-specific OAuth client IDs for the Homelab MCP resource.
     * These clients are pre-registered so Claude, Gemini and Grok can use "Use your own
     * OAuth client" / manual registration instead of receiving random DCR client IDs.
     */
    private void seedHomelabMcpClients() {
        if (isBlank(homelabMcpResource)) {
            log.warn("Skipping named Homelab MCP clients: auth.client.homelab-mcp.resource is not configured");
            return;
        }

        seedHomelabMcpClient(
                homelabClaudeClientId, "Homelab MCP - Claude",
                homelabClaudeRedirectUris, false, false, null);
        seedHomelabMcpClient(
                homelabGeminiClientId, "Homelab MCP - Gemini",
                homelabGeminiRedirectUris, true, false, null);

        if (isBlank(homelabGrokClientSecret)) {
            log.warn("Skipping named Homelab Grok client '{}': configure auth.client.homelab-mcp.grok.client-secret",
                    homelabGrokClientId);
        } else {
            seedHomelabMcpClient(
                    homelabGrokClientId, "Homelab MCP - Grok",
                    homelabGrokRedirectUris, false, true, homelabGrokClientSecret);
        }
    }

    private void seedHomelabMcpClient(
            String clientId,
            String clientName,
            List<String> redirectUris,
            boolean geminiDynamicRedirect,
            boolean confidential,
            String clientSecret) {

        List<String> uris = clean(redirectUris);
        if (isBlank(clientId) || (uris.isEmpty() && !geminiDynamicRedirect)) {
            log.warn("Skipping incomplete named Homelab MCP client '{}': client ID and redirect URI are required",
                    clientId);
            return;
        }

        List<String> registeredUris = uris.isEmpty() && geminiDynamicRedirect
                ? List.of(GEMINI_REDIRECT_URI_PLACEHOLDER) : uris;
        ClientSettings.Builder settings = ClientSettings.builder()
                .requireProofKey(true)
                .requireAuthorizationConsent(true)
                .setting(MCP_RESOURCE_SETTING, homelabMcpResource);
        if (geminiDynamicRedirect) {
            settings.setting(GEMINI_DYNAMIC_REDIRECT_SETTING, true);
        }

        RegisteredClient.Builder builder = base(clientId, clientName, registeredUris)
                .scope("homelab.read")
                .clientSettings(settings.build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .reuseRefreshTokens(false)
                        .build());

        if (confidential) {
            builder.clientSecret(passwordEncoder.encode(clientSecret))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
        } else {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        }

        save(builder.build());
    }

    private void seedClaude() {
        List<String> uris = clean(claudeRedirectUris);
        if (isBlank(claudeClientId) || uris.isEmpty()) {
            return;
        }
        boolean confidential = !isBlank(claudeClientSecret);
        if (!confidential) {
            log.warn("auth.client.claude.client-secret is not set: registering '{}' as a PUBLIC client. "
                    + "Refresh tokens are disabled for MCP clients, so the connector must sign in again whenever its access token expires.",
                    claudeClientId);
        }

        RegisteredClient.Builder builder = base(claudeClientId, "Claude connector", uris)
                .scope("kanban.read")
                .scope("kanban.write")
                .clientSettings(mcpClientSettings(true))
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .build());
        if (confidential) {
            builder.clientSecret(passwordEncoder.encode(claudeClientSecret))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
        } else {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        }
        save(builder.build());
    }

    private void seedWeb() {
        List<String> uris = clean(webRedirectUris);
        if (isBlank(webClientId) || uris.isEmpty()) {
            return;
        }
        RegisteredClient.Builder builder = base(webClientId, "Kanban web UI", uris)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .scope("openid")
                .scope("profile")
                .scope("email")
                .scope("kanban.read")
                .scope("kanban.write");
        ClientSettings.Builder settings = ClientSettings.builder()
                .requireProofKey(true)
                .requireAuthorizationConsent(false);
        if (!webResourceUri.isBlank()) {
            settings.setting(RESOURCE_URI_SETTING, webResourceUri);
        }
        builder.clientSettings(settings.build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(webAccessTokenTtl)
                        .build());
        save(builder.build());
    }

    /**
     * Registers additional first-party browser applications from Config Server. Each application
     * gets its own client ID, exact callback allow-list, scopes and API audience.
     */
    private void seedConfiguredApplications() {
        for (ApplicationClientProperties.ApplicationClient application : applicationClients.getApplications()) {
            String clientId = application.getClientId() == null ? "" : application.getClientId().trim();
            List<String> uris = clean(application.getRedirectUris());
            List<String> scopes = clean(application.getScopes());
            String resourceUri = application.getResourceUri() == null ? "" : application.getResourceUri().trim();
            if (isBlank(clientId) || isBlank(application.getName()) || uris.isEmpty() || scopes.isEmpty()
                    || isBlank(resourceUri)) {
                log.warn("Skipping incomplete auth.clients application client '{}': client-id, name, redirect-uris, scopes and resource-uri are required",
                        clientId);
                continue;
            }
            RegisteredClient.Builder builder = base(clientId, application.getName().trim(), uris)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .clientSettings(ClientSettings.builder()
                            .requireProofKey(true)
                            .requireAuthorizationConsent(false)
                            .setting(RESOURCE_URI_SETTING, resourceUri)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                            .accessTokenTimeToLive(Duration.ofHours(8))
                            .build());
            scopes.forEach(builder::scope);
            save(builder.build());
        }
    }

    private void seedMcpClient(String clientId, String clientSecret, String clientName, List<String> redirectUris,
                               boolean allowEmptyRedirectUris, boolean geminiDynamicRedirect) {
        List<String> uris = clean(redirectUris);
        if (isBlank(clientId) || (!allowEmptyRedirectUris && uris.isEmpty())) {
            return;
        }
        if (isBlank(mcpResource)) {
            log.error("Cannot register MCP OAuth client '{}': auth.client.mcp.resource is not configured", clientId);
            return;
        }

        boolean confidential = !isBlank(clientSecret);
        TokenSettings.Builder tokenSettings = TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .accessTokenTimeToLive(Duration.ofHours(1));
        // RegisteredClient requires at least one redirect URI for authorization_code clients.
        // This reserved placeholder is never accepted by GeminiRedirectUriValidator.
        List<String> registeredUris = uris.isEmpty() && geminiDynamicRedirect
                ? List.of(GEMINI_REDIRECT_URI_PLACEHOLDER) : uris;
        RegisteredClient.Builder builder = base(clientId, clientName, registeredUris)
                .scope("kanban.read")
                .scope("kanban.write")
                .clientSettings(mcpClientSettings(true, geminiDynamicRedirect))
                .tokenSettings(tokenSettings.build());

        if (confidential) {
            builder.clientSecret(passwordEncoder.encode(clientSecret))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
        } else {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        }
        save(builder.build());
    }

    private ClientSettings mcpClientSettings(boolean requireConsent) {
        return mcpClientSettings(requireConsent, false);
    }

    private ClientSettings mcpClientSettings(boolean requireConsent, boolean geminiDynamicRedirect) {
        ClientSettings.Builder builder = ClientSettings.builder()
                .requireProofKey(true)
                .requireAuthorizationConsent(requireConsent);
        if (!isBlank(mcpResource)) {
            builder.setting(MCP_RESOURCE_SETTING, mcpResource);
        }
        if (!mcpBackendResource.isBlank()) {
            builder.setting(MCP_BACKEND_RESOURCE_SETTING, mcpBackendResource);
        }
        if (geminiDynamicRedirect) {
            builder.setting(GEMINI_DYNAMIC_REDIRECT_SETTING, true);
        }
        return builder.build();
    }

    private RegisteredClient.Builder base(String clientId, String name, List<String> redirectUris) {
        RegisteredClient existing = clients.findByClientId(clientId);
        RegisteredClient.Builder builder = RegisteredClient
                .withId(existing != null ? existing.getId() : UUID.randomUUID().toString())
                .clientId(clientId)
                .clientName(name)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        redirectUris.forEach(builder::redirectUri);
        return builder;
    }

    private void save(RegisteredClient client) {
        clients.save(client);
        log.info("Registered OAuth client '{}' ({})", client.getClientId(),
                client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE) ? "public" : "confidential");
    }

    private static List<String> clean(List<String> values) {
        return values == null ? List.of() : values.stream().map(String::trim).filter(v -> !v.isEmpty()).toList();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}