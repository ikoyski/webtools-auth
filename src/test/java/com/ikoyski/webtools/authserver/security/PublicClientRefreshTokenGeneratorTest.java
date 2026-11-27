package com.ikoyski.webtools.authserver.security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

class PublicClientRefreshTokenGeneratorTest {

    private final OAuth2TokenGenerator<OAuth2RefreshToken> delegate = mock(OAuth2TokenGenerator.class);
    private final PublicClientRefreshTokenGenerator generator = new PublicClientRefreshTokenGenerator(delegate);

    @Test
    void issuesRotatingRefreshTokensForPublicPkceClientsThatOptIn() {
        RegisteredClient client = publicClient(true, true);
        OAuth2TokenContext context = context(client, AuthorizationGrantType.AUTHORIZATION_CODE);

        OAuth2RefreshToken first = generator.generate(context);
        OAuth2RefreshToken second = generator.generate(context);

        assertNotNull(first);
        assertNotNull(second);
        assertNotEquals(first.getTokenValue(), second.getTokenValue());
        assertEquals(Duration.ofDays(30), Duration.between(first.getIssuedAt(), first.getExpiresAt()));
        verifyNoInteractions(delegate);
    }

    @Test
    void doesNotIssueRefreshTokensWhenPublicClientHasNotOptedIn() {
        OAuth2RefreshToken token = generator.generate(context(
                publicClient(false, true), AuthorizationGrantType.AUTHORIZATION_CODE));

        assertNull(token);
        verifyNoInteractions(delegate);
    }

    @Test
    void doesNotIssueRefreshTokensToPublicAuthorizationCodeClientWithoutPkce() {
        OAuth2RefreshToken token = generator.generate(context(
                publicClient(true, false), AuthorizationGrantType.AUTHORIZATION_CODE));

        assertNull(token);
        verifyNoInteractions(delegate);
    }

    @Test
    void delegatesConfidentialClientRefreshTokenGenerationToSpring() {
        RegisteredClient client = RegisteredClient.withId("confidential")
                .clientId("confidential")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(TokenSettings.builder().refreshTokenTimeToLive(Duration.ofDays(30)).build())
                .build();
        OAuth2RefreshToken expected = new OAuth2RefreshToken("delegated", Instant.now(), Instant.now().plusSeconds(60));
        when(delegate.generate(any())).thenReturn(expected);

        assertSame(expected, generator.generate(context(client, AuthorizationGrantType.AUTHORIZATION_CODE)));
        verify(delegate).generate(any());
    }

    private static RegisteredClient publicClient(boolean refreshEnabled, boolean pkce) {
        RegisteredClient.Builder builder = RegisteredClient.withId("public")
                .clientId("public")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .clientSettings(ClientSettings.builder().requireProofKey(pkce).build())
                .tokenSettings(TokenSettings.builder()
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .reuseRefreshTokens(false)
                        .build());
        if (refreshEnabled) builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        return builder.build();
    }

    private static OAuth2TokenContext context(RegisteredClient client, AuthorizationGrantType grantType) {
        OAuth2TokenContext context = mock(OAuth2TokenContext.class);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.REFRESH_TOKEN);
        when(context.getRegisteredClient()).thenReturn(client);
        when(context.getAuthorizationGrantType()).thenReturn(grantType);
        return context;
    }
}
