package com.ikoyski.webtools.authserver.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

class AuthorizationServerTokenGeneratorTest {

    @Test
    void composedTokenGeneratorUsesCustomGeneratorForOptedInPublicClients() {
        @SuppressWarnings("unchecked")
        JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);
        OAuth2TokenGenerator<?> tokenGenerator =
                new AuthorizationServerConfig().tokenGenerator(jwkSource, context -> {});

        RegisteredClient client = RegisteredClient.withId("public-client")
                .clientId("public-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://client.example/callback")
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .tokenSettings(TokenSettings.builder()
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .reuseRefreshTokens(false)
                        .build())
                .build();

        OAuth2TokenContext context = mock(OAuth2TokenContext.class);
        when(context.getTokenType()).thenReturn(new OAuth2TokenType("refresh_token"));
        when(context.getRegisteredClient()).thenReturn(client);
        when(context.getAuthorizationGrantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);

        OAuth2RefreshToken generated = (OAuth2RefreshToken) tokenGenerator.generate(context);

        assertNotNull(generated);
        assertEquals(Duration.ofDays(30), Duration.between(generated.getIssuedAt(), generated.getExpiresAt()));
    }
}
