package com.ikoyski.webtools.authserver.security;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

class OAuthProtocolErrorEntryPointMatcherTest {

    @Test
    void genericAcceptHeaderDoesNotSelectInteractiveHtmlLoginEntryPoint() {
        MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
        matcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/token");
        request.addHeader("Accept", MediaType.ALL_VALUE);

        assertFalse(matcher.matches(request));
    }

    @Test
    void explicitHtmlAcceptStillSelectsInteractiveLoginEntryPoint() {
        MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
        matcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        request.addHeader("Accept", MediaType.TEXT_HTML_VALUE);

        assertTrue(matcher.matches(request));
    }
}
