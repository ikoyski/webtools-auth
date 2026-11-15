package com.ikoyski.webtools.authserver.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
    private static final String GEMINI_PLACEHOLDER =
            "https://oauth-redirect.googleusercontent.com/r/__dynamic_callback_placeholder__";

    @Mock
    private RegisteredClientRepository clients;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Test
    void seedsStableHomelabClientsWithOnlyHomelabAudienceAndNoRefreshTokens() throws Exception {
        when(clients.findByClientId(anyString())).thenReturn(null);
        ClientSeeder seeder = seeder("test-grok-client-secret");

        seeder.run(new DefaultApplicationArguments());

        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(clients, times(3)).save(captor.capture());
        Map<String, RegisteredClient> registered = captor.getAllValues().stream()
                .collect(Collectors.toMap(RegisteredClient::getClientId, Function.identity()));

        assertEquals(Set.of("homelab-claude", "homelab-gemini", "homelab-grok"), registered.keySet());
        assertPublicHomelabClient(registered.get("homelab-claude"));
        assertEquals(Set.of(CLAUDE_CALLBACK), registered.get("homelab-claude").getRedirectUris());

        RegisteredClient gemini = registered.get("homelab-gemini");
        assertPublicHomelabClient(gemini);
        assertEquals(Set.of(GEMINI_PLACEHOLDER), gemini.getRedirectUris());
        assertEquals(Boolean.TRUE,
                gemini.getClientSettings().getSetting(ClientSeeder.GEMINI_DYNAMIC_REDIRECT_SETTING));

        RegisteredClient grok = registered.get("homelab-grok");
        assertEquals(Set.of("homelab.read"), grok.getScopes());
        assertEquals(Set.of(AuthorizationGrantType.AUTHORIZATION_CODE), grok.getAuthorizationGrantTypes());
        assertEquals(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_POST),
                grok.getClientAuthenticationMethods());
        assertTrue(passwordEncoder.matches("test-grok-client-secret", grok.getClientSecret()));
        assertHomelabResourceOnly(grok);
        assertEquals(Duration.ofHours(1), grok.getTokenSettings().getAccessTokenTimeToLive());
    }

    @Test
    void doesNotSeedGrokWhenItsSecretIsNotConfigured() throws Exception {
        when(clients.findByClientId(anyString())).thenReturn(null);
        ClientSeeder seeder = seeder("");

        seeder.run(new DefaultApplicationArguments());

        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(clients, times(2)).save(captor.capture());
        assertEquals(Set.of("homelab-claude", "homelab-gemini"),
                captor.getAllValues().stream().map(RegisteredClient::getClientId).collect(Collectors.toSet()));
    }

    private ClientSeeder seeder(String grokSecret) {
        return new ClientSeeder(
                clients,
                passwordEncoder,
                "", "", List.of(),
                "", List.of(), Duration.ofHours(8), "",
                new ApplicationClientProperties(),
                "", "",
                "", "", List.of(),
                "", "", List.of(),
                HOMELAB_RESOURCE,
                "homelab-claude", List.of(CLAUDE_CALLBACK),
                "homelab-gemini", List.of(),
                "homelab-grok", grokSecret, List.of(GROK_CALLBACK));
    }

    private static void assertPublicHomelabClient(RegisteredClient client) {
        assertEquals(Set.of("homelab.read"), client.getScopes());
        assertEquals(Set.of(AuthorizationGrantType.AUTHORIZATION_CODE), client.getAuthorizationGrantTypes());
        assertEquals(Set.of(ClientAuthenticationMethod.NONE), client.getClientAuthenticationMethods());
        assertTrue(client.getClientSettings().isRequireProofKey());
        assertTrue(client.getClientSettings().isRequireAuthorizationConsent());
        assertHomelabResourceOnly(client);
        assertEquals(Duration.ofHours(1), client.getTokenSettings().getAccessTokenTimeToLive());
        assertNull(client.getTokenSettings().getReuseRefreshTokens() ? "refresh tokens must not be enabled" : null);
    }

    private static void assertHomelabResourceOnly(RegisteredClient client) {
        assertEquals(HOMELAB_RESOURCE,
                client.getClientSettings().getSetting(ClientSeeder.MCP_RESOURCE_SETTING));
        assertNull(client.getClientSettings().getSetting(ClientSeeder.MCP_BACKEND_RESOURCE_SETTING));
    }
}
