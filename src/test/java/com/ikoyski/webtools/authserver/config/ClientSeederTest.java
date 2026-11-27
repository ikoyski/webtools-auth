package com.ikoyski.webtools.authserver.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@ExtendWith(MockitoExtension.class)
class ClientSeederTest {

    private static final String HOMELAB_RESOURCE = "https://homelab-mcp.ikoyski.top/mcp";
    private static final String CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback";
    private static final String GROK_CALLBACK = "https://grok.com/connectors-oauth-exchange-code/";
    private static final String ANTIGRAVITY_CALLBACK = "https://antigravity.google/oauth-callback";
    private static final String GEMINI_PLACEHOLDER =
            "https://oauth-redirect.googleusercontent.com/r/__dynamic_callback_placeholder__";

    @Mock
    private RegisteredClientRepository clients;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Test
    void seedsStableHomelabClientsWithOnlyHomelabAudienceAndNoRefreshTokens() throws Exception {
        when(clients.findByClientId(anyString())).thenReturn(null);
        ClientSeeder seeder = seeder();

        seeder.run(new DefaultApplicationArguments());

        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(clients, times(4)).save(captor.capture());
        Map<String, RegisteredClient> registered = captor.getAllValues().stream()
                .collect(Collectors.toMap(RegisteredClient::getClientId, Function.identity()));

        assertEquals(Set.of("homelab-claude", "homelab-gemini", "homelab-grok", "homelab-antigravity"),
                registered.keySet());
        assertPublicHomelabClient(registered.get("homelab-claude"));
        assertEquals(Set.of(CLAUDE_CALLBACK, "https://claude.com/api/mcp/auth_callback"),
                registered.get("homelab-claude").getRedirectUris());

        RegisteredClient gemini = registered.get("homelab-gemini");
        assertPublicHomelabClient(gemini);
        assertEquals(Set.of(GEMINI_PLACEHOLDER), gemini.getRedirectUris());
        assertEquals(Boolean.TRUE,
                gemini.getClientSettings().getSetting(ClientSeeder.GEMINI_DYNAMIC_REDIRECT_SETTING));

        RegisteredClient grok = registered.get("homelab-grok");
        assertEquals(Set.of("homelab.read"), grok.getScopes());
        assertEquals(Set.of(AuthorizationGrantType.AUTHORIZATION_CODE), grok.getAuthorizationGrantTypes());
        assertEquals(Set.of(ClientAuthenticationMethod.NONE),
                grok.getClientAuthenticationMethods());
        assertNull(grok.getClientSecret());
        assertTrue(grok.getClientSettings().isRequireProofKey());
        assertTrue(grok.getClientSettings().isRequireAuthorizationConsent());
        assertFalse(grok.getTokenSettings().isReuseRefreshTokens());
        assertHomelabResourceOnly(grok);
        assertEquals(Duration.ofHours(1), grok.getTokenSettings().getAccessTokenTimeToLive());

        RegisteredClient antigravity = registered.get("homelab-antigravity");
        assertPublicHomelabClient(antigravity);
        assertEquals(Set.of(ANTIGRAVITY_CALLBACK), antigravity.getRedirectUris());
    }

    @Test
    void seedsKanbanClientsWithKanbanAudiencesAndKeepsWebClientSeparate() throws Exception {
        when(clients.findByClientId(anyString())).thenReturn(null);
        MockEnvironment environment = new MockEnvironment()
                .withProperty("auth.clients.kanban-claude.redirect-uris[0]", CLAUDE_CALLBACK)
                .withProperty("auth.clients.kanban-web.redirect-uris[0]",
                        "https://pages.ikoyski.top/kanban/kanban.html")
                .withProperty("auth.clients.kanban-chatgpt.redirect-uris[0]",
                        "https://chatgpt.com/connector_platform_oauth_redirect")
                .withProperty("auth.clients.kanban-antigravity.redirect-uris[0]", ANTIGRAVITY_CALLBACK)
                .withProperty("auth.clients.homelab-claude.redirect-uris[0]", CLAUDE_CALLBACK)
                .withProperty("auth.clients.homelab-grok.redirect-uris[0]", GROK_CALLBACK)
                .withProperty("auth.clients.homelab-antigravity.redirect-uris[0]", ANTIGRAVITY_CALLBACK);
        ClientSeeder seeder = new ClientSeeder(
                clients,
                passwordEncoder,
                "kanban-claude", "",
                "kanban-web",
                Duration.ofHours(8), "https://api.ikoyski.top/kanban-backend",
                new ApplicationClientProperties(),
                environment,
                "https://api.ikoyski.top/kanban-mcp/mcp",
                "https://api.ikoyski.top/kanban-backend",
                "kanban-chatgpt", "",
                "kanban-gemini", "",
                "kanban-antigravity",
                HOMELAB_RESOURCE,
                "homelab-claude",
                "homelab-gemini",
                "homelab-grok",
                "homelab-antigravity");

        seeder.run(new DefaultApplicationArguments());

        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(clients, times(9)).save(captor.capture());
        Map<String, RegisteredClient> registered = captor.getAllValues().stream()
                .collect(Collectors.toMap(RegisteredClient::getClientId, Function.identity()));

        RegisteredClient kanbanClaude = registered.get("kanban-claude");
        assertEquals(Set.of("kanban.read", "kanban.write"), kanbanClaude.getScopes());
        assertEquals("https://api.ikoyski.top/kanban-mcp/mcp",
                kanbanClaude.getClientSettings().getSetting(ClientSeeder.MCP_RESOURCE_SETTING));
        assertEquals("https://api.ikoyski.top/kanban-backend",
                kanbanClaude.getClientSettings().getSetting(ClientSeeder.MCP_BACKEND_RESOURCE_SETTING));

        RegisteredClient kanbanAntigravity = registered.get("kanban-antigravity");
        assertEquals(Set.of("kanban.read", "kanban.write"), kanbanAntigravity.getScopes());
        assertEquals(Set.of(ANTIGRAVITY_CALLBACK), kanbanAntigravity.getRedirectUris());
        assertEquals(Set.of(AuthorizationGrantType.AUTHORIZATION_CODE),
                kanbanAntigravity.getAuthorizationGrantTypes());
        assertEquals(Set.of(ClientAuthenticationMethod.NONE),
                kanbanAntigravity.getClientAuthenticationMethods());
        assertNull(kanbanAntigravity.getClientSecret());
        assertTrue(kanbanAntigravity.getClientSettings().isRequireProofKey());
        assertTrue(kanbanAntigravity.getClientSettings().isRequireAuthorizationConsent());
        assertEquals("https://api.ikoyski.top/kanban-mcp/mcp",
                kanbanAntigravity.getClientSettings().getSetting(ClientSeeder.MCP_RESOURCE_SETTING));
        assertEquals("https://api.ikoyski.top/kanban-backend",
                kanbanAntigravity.getClientSettings().getSetting(ClientSeeder.MCP_BACKEND_RESOURCE_SETTING));
        assertEquals(Duration.ofHours(1),
                kanbanAntigravity.getTokenSettings().getAccessTokenTimeToLive());

        RegisteredClient kanbanWeb = registered.get("kanban-web");
        assertEquals(Set.of("openid", "profile", "email", "kanban.read", "kanban.write"),
                kanbanWeb.getScopes());
        assertEquals("https://api.ikoyski.top/kanban-backend",
                kanbanWeb.getClientSettings().getSetting(ClientSeeder.RESOURCE_URI_SETTING));
        assertNull(kanbanWeb.getClientSettings().getSetting(ClientSeeder.MCP_RESOURCE_SETTING));
        assertEquals(Duration.ofHours(8), kanbanWeb.getTokenSettings().getAccessTokenTimeToLive());

        RegisteredClient homelabClaude = registered.get("homelab-claude");
        assertPublicHomelabClient(homelabClaude);
        assertEquals(Set.of(CLAUDE_CALLBACK), homelabClaude.getRedirectUris());
    }

    private ClientSeeder seeder() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("auth.clients.homelab-claude.redirect-uris[0]", CLAUDE_CALLBACK)
                .withProperty("auth.clients.homelab-claude.redirect-uris[1]",
                        "https://claude.com/api/mcp/auth_callback")
                .withProperty("auth.clients.homelab-grok.redirect-uris[0]", GROK_CALLBACK)
                .withProperty("auth.clients.homelab-antigravity.redirect-uris[0]", ANTIGRAVITY_CALLBACK);
        return new ClientSeeder(
                clients,
                passwordEncoder,
                "", "",
                "",
                Duration.ofHours(8), "",
                new ApplicationClientProperties(),
                environment,
                "", "",
                "", "",
                "", "",
                "",
                HOMELAB_RESOURCE,
                "homelab-claude",
                "homelab-gemini",
                "homelab-grok",
                "homelab-antigravity");
    }

    private static void assertPublicHomelabClient(RegisteredClient client) {
        assertEquals(Set.of("homelab.read"), client.getScopes());
        assertEquals(Set.of(AuthorizationGrantType.AUTHORIZATION_CODE), client.getAuthorizationGrantTypes());
        assertEquals(Set.of(ClientAuthenticationMethod.NONE), client.getClientAuthenticationMethods());
        assertTrue(client.getClientSettings().isRequireProofKey());
        assertTrue(client.getClientSettings().isRequireAuthorizationConsent());
        assertHomelabResourceOnly(client);
        assertEquals(Duration.ofHours(1), client.getTokenSettings().getAccessTokenTimeToLive());
        assertFalse(client.getTokenSettings().isReuseRefreshTokens());
    }

    private static void assertHomelabResourceOnly(RegisteredClient client) {
        assertEquals(HOMELAB_RESOURCE,
                client.getClientSettings().getSetting(ClientSeeder.MCP_RESOURCE_SETTING));
        assertNull(client.getClientSettings().getSetting(ClientSeeder.MCP_BACKEND_RESOURCE_SETTING));
    }
}
