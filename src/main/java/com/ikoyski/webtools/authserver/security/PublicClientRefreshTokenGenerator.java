package com.ikoyski.webtools.authserver.security;

import java.time.Instant;
import java.util.Base64;
import java.security.SecureRandom;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * Allows refresh-token issuance to public clients only when the registered client explicitly
 * enables the refresh_token grant and requires PKCE for authorization_code.
 *
 * Confidential clients retain Spring Authorization Server's standard refresh-token generator.
 * Public refresh tokens are random opaque bearer credentials and rely on the authorization
 * server's standard refresh-token provider for validation, persistence, expiry and rotation.
 */
public final class PublicClientRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private final OAuth2TokenGenerator<OAuth2RefreshToken> defaultGenerator;

    public PublicClientRefreshTokenGenerator(OAuth2TokenGenerator<OAuth2RefreshToken> defaultGenerator) {
        this.defaultGenerator = defaultGenerator;
    }

    @Override
    public OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!new OAuth2TokenType("refresh_token").equals(context.getTokenType())) {
            return null;
        }

        RegisteredClient client = context.getRegisteredClient();
        if (client == null
                || !client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            return null;
        }

        boolean publicClient = client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE);
        if (!publicClient) {
            return defaultGenerator.generate(context);
        }

        // Public clients must use PKCE for the authorization-code grant before refresh tokens
        // can be issued. This also prevents a misconfigured registration from opting in unsafely.
        AuthorizationGrantType grantType = context.getAuthorizationGrantType();
        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(grantType)) {
            if (!client.getClientSettings().isRequireProofKey()) {
                return null;
            }
        } else if (!AuthorizationGrantType.REFRESH_TOKEN.equals(grantType)) {
            // Public refresh tokens are issued only from the PKCE authorization-code flow
            // and rotated only when a valid refresh token is exchanged.
            return null;
        }

        byte[] random = new byte[32];
        SECURE_RANDOM.nextBytes(random);
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(client.getTokenSettings().getRefreshTokenTimeToLive());
        String tokenValue = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        return new OAuth2RefreshToken(tokenValue, issuedAt, expiresAt);
    }
}
