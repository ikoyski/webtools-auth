package com.ikoyski.webtools.authserver.security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

class PublicClientRefreshTokenAuthenticationProviderTest {

    private final RegisteredClientRepository clients = mock(RegisteredClientRepository.class);
    private final PublicClientRefreshTokenAuthenticationProvider provider =
            new PublicClientRefreshTokenAuthenticationProvider(clients);

    @Test
    void authenticatesRegisteredPublicClientForRefreshWithoutCodeVerifier() {
        RegisteredClient client = publicClient(true);
        when(clients.findByClientId("kanban-antigravity")).thenReturn(client);

        Authentication result = provider.authenticate(refreshAuthentication("kanban-antigravity"));

        assertInstanceOf(OAuth2ClientAuthenticationToken.class, result);
        OAuth2ClientAuthenticationToken authenticated = (OAuth2ClientAuthenticationToken) result;
        assertTrue(authenticated.isAuthenticated());
        assertSame(client, authenticated.getRegisteredClient());
        assertEquals(ClientAuthenticationMethod.NONE, authenticated.getClientAuthenticationMethod());
        verify(clients).findByClientId("kanban-antigravity");
    }

    @Test
    void rejectsUnknownPublicClient() {
        when(clients.findByClientId("unknown")).thenReturn(null);

        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider.authenticate(refreshAuthentication("unknown")));

        assertEquals("invalid_client", exception.getError().getErrorCode());
    }

    @Test
    void rejectsRegisteredConfidentialClientUsingPublicAuthentication() {
        RegisteredClient confidential = RegisteredClient.withId("confidential-id")
                .clientId("confidential")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();
        when(clients.findByClientId("confidential")).thenReturn(confidential);

        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider.authenticate(refreshAuthentication("confidential")));

        assertEquals("invalid_client", exception.getError().getErrorCode());
    }

    @Test
    void rejectsPublicClientNotRegisteredForRefreshGrant() {
        when(clients.findByClientId("public-no-refresh")).thenReturn(publicClient(false));

        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider.authenticate(refreshAuthentication("public-no-refresh")));

        assertEquals("unauthorized_client", exception.getError().getErrorCode());
    }

    @Test
    void ignoresNonRefreshPublicClientAuthentication() {
        Authentication authentication = new OAuth2ClientAuthenticationToken(
                "kanban-antigravity",
                ClientAuthenticationMethod.NONE,
                null,
                Map.of(OAuth2ParameterNames.GRANT_TYPE, "authorization_code"));

        assertNull(provider.authenticate(authentication));
        verifyNoInteractions(clients);
    }

    private static Authentication refreshAuthentication(String clientId) {
        return new OAuth2ClientAuthenticationToken(
                clientId,
                ClientAuthenticationMethod.NONE,
                null,
                Map.of(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue()));
    }

    private static RegisteredClient publicClient(boolean refreshEnabled) {
        RegisteredClient.Builder builder = RegisteredClient.withId("public-id")
                .clientId("kanban-antigravity")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example/callback")
                .clientSettings(ClientSettings.builder().requireProofKey(true).build());
        if (refreshEnabled) {
            builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        }
        return builder.build();
    }
}
