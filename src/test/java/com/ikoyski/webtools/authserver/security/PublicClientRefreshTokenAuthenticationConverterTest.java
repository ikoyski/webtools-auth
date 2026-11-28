package com.ikoyski.webtools.authserver.security;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

class PublicClientRefreshTokenAuthenticationConverterTest {

    private final PublicClientRefreshTokenAuthenticationConverter converter =
            new PublicClientRefreshTokenAuthenticationConverter();

    @Test
    void convertsPublicRefreshTokenRequestWithoutCodeVerifier() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/token");
        request.setParameter(OAuth2ParameterNames.GRANT_TYPE, "refresh_token");
        request.setParameter(OAuth2ParameterNames.CLIENT_ID, "kanban-antigravity");
        request.setParameter(OAuth2ParameterNames.REFRESH_TOKEN, "opaque-refresh-token");

        OAuth2ClientAuthenticationToken result =
                (OAuth2ClientAuthenticationToken) converter.convert(request);

        assertNotNull(result);
        assertEquals("kanban-antigravity", result.getPrincipal());
        assertEquals(ClientAuthenticationMethod.NONE, result.getClientAuthenticationMethod());
        assertEquals("refresh_token",
                result.getAdditionalParameters().get(OAuth2ParameterNames.GRANT_TYPE));
    }

    @Test
    void ignoresAuthorizationCodeRequestsSoSpringPkceConverterCanHandleThem() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/token");
        request.setParameter(OAuth2ParameterNames.GRANT_TYPE, "authorization_code");
        request.setParameter(OAuth2ParameterNames.CLIENT_ID, "kanban-antigravity");
        request.setParameter(OAuth2ParameterNames.CODE, "authorization-code");
        request.setParameter("code_verifier", "pkce-verifier");

        assertNull(converter.convert(request));
    }

    @Test
    void rejectsRefreshRequestWithoutExactlyOneClientId() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/token");
        request.setParameter(OAuth2ParameterNames.GRANT_TYPE, "refresh_token");

        OAuth2AuthenticationException exception =
                assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

        assertEquals("invalid_request", exception.getError().getErrorCode());
    }

    @Test
    void rejectsDuplicateClientIds() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/token");
        request.setParameter(OAuth2ParameterNames.GRANT_TYPE, "refresh_token");
        request.addParameter(OAuth2ParameterNames.CLIENT_ID, "kanban-antigravity");
        request.addParameter(OAuth2ParameterNames.CLIENT_ID, "another-client");

        OAuth2AuthenticationException exception =
                assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

        assertEquals("invalid_request", exception.getError().getErrorCode());
    }

    @Test
    void rejectsDuplicateGrantTypes() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/token");
        request.addParameter(OAuth2ParameterNames.GRANT_TYPE, "refresh_token");
        request.addParameter(OAuth2ParameterNames.GRANT_TYPE, "authorization_code");
        request.setParameter(OAuth2ParameterNames.CLIENT_ID, "kanban-antigravity");

        OAuth2AuthenticationException exception =
                assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

        assertEquals("invalid_request", exception.getError().getErrorCode());
    }
}
