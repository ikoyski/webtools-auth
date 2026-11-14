package com.ikoyski.webtools.authserver.security;

import java.io.IOException;
import java.util.regex.Pattern;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

/**
 * Records a privacy-safe federated sign-in failure event. Provider response
 * bodies, OAuth parameters, exception messages and credentials are never logged.
 */
@Component
public class FederatedLoginFailureHandler implements AuthenticationFailureHandler {

    private static final Logger log = LoggerFactory.getLogger(FederatedLoginFailureHandler.class);
    private static final String CALLBACK_PREFIX = "/login/oauth2/code/";
    private static final Pattern SAFE_PROVIDER = Pattern.compile("[A-Za-z0-9_-]{1,64}");

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        String provider = providerFromCallbackPath(request.getRequestURI());
        log.warn("federated_sign_in_failed provider={} failureType={}",
                provider, exception.getClass().getSimpleName());

        response.sendRedirect(request.getContextPath() + "/login?error");
    }

    private static String providerFromCallbackPath(String requestUri) {
        int callbackIndex = requestUri.lastIndexOf(CALLBACK_PREFIX);
        if (callbackIndex < 0) {
            return "unknown";
        }

        String candidate = requestUri.substring(callbackIndex + CALLBACK_PREFIX.length());
        return SAFE_PROVIDER.matcher(candidate).matches() ? candidate : "unknown";
    }
}
