package com.ikoyski.webtools.authserver.security;

import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.ikoyski.webtools.authserver.config.ClientSeeder;
import com.ikoyski.webtools.authserver.config.GeminiRedirectUriValidator;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Protocol endpoints: /oauth2/authorize, /oauth2/token, /oauth2/jwks,
     * /.well-known/oauth-authorization-server, etc. Browsers that are not signed in are sent
     * to /login. OIDC is enabled for standardized identity tokens and UserInfo. Restricted MCP client registration
     * is advertised only when explicitly enabled for an approved environment.
     * CORS is enabled so a browser app can call the token endpoint (see CorsConfig).
     */
    @Bean
    @Order(1)
    @SuppressWarnings("deprecation") // applyDefaultSecurity is deprecated since 1.4 but still supported
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http, GeminiRedirectUriValidator geminiRedirectUriValidator,
            OAuth2TokenGenerator<?> tokenGenerator,
            RegisteredClientRepository registeredClientRepository,
            @org.springframework.beans.factory.annotation.Value("${auth.mcp.client-registration.enabled:false}") boolean mcpClientRegistrationEnabled,
            @org.springframework.beans.factory.annotation.Value("${auth.issuer}") String issuer) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
        authorizationServerConfigurer.tokenGenerator(tokenGenerator);
        authorizationServerConfigurer.clientAuthentication(clientAuthentication -> {
            // Public clients cannot use a client secret. During refresh, authenticate the registered
            // client_id without requiring the authorization-code-only PKCE code_verifier.
            // Keep Spring's JWT, Basic, Post, PKCE and X.509 converters ahead of this fallback.
            // The default PKCE converter intentionally does not match refresh grants.
            clientAuthentication.authenticationConverters(converters ->
                    converters.add(new PublicClientRefreshTokenAuthenticationConverter()));
            clientAuthentication.authenticationProviders(providers ->
                    providers.add(0, new PublicClientRefreshTokenAuthenticationProvider(registeredClientRepository)));
        });
        authorizationServerConfigurer.oidc(Customizer.withDefaults());
        if (mcpClientRegistrationEnabled) {
            authorizationServerConfigurer.authorizationServerMetadataEndpoint(endpoint ->
                    endpoint.authorizationServerMetadataCustomizer(metadata -> {
                        metadata.claim("registration_endpoint", issuer + "/oauth2/register");
                        metadata.claim("scopes_supported", List.of("kanban.read", "kanban.write", "homelab.read"));
                        metadata.claim("token_endpoint_auth_methods_supported",
                                List.of("none", "client_secret_post"));
                    }));
        }
        authorizationServerConfigurer.authorizationEndpoint(endpoint ->
                endpoint.authenticationProviders(configureAuthorizationCodeValidator(geminiRedirectUriValidator)));

        http.cors(Customizer.withDefaults());
        MediaTypeRequestMatcher browserHtmlMatcher =
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
        // Generic OAuth HTTP clients commonly send Accept: */*. Do not interpret that as
        // a browser request and redirect protocol errors to the interactive HTML login page.
        browserHtmlMatcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));
        http.exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"), browserHtmlMatcher));
        return http.build();
    }

    private Consumer<List<AuthenticationProvider>> configureAuthorizationCodeValidator(
            GeminiRedirectUriValidator geminiRedirectUriValidator) {
        return providers -> providers.forEach(provider -> {
            if (provider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider authorizationCodeProvider) {
                Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> redirectValidator = context -> {
                    Object isGeminiDynamic = context.getRegisteredClient().getClientSettings()
                            .getSetting(ClientSeeder.GEMINI_DYNAMIC_REDIRECT_SETTING);
                    if (Boolean.TRUE.equals(isGeminiDynamic)) {
                        geminiRedirectUriValidator.accept(context);
                    } else {
                        OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
                                .accept(context);
                    }
                };
                authorizationCodeProvider.setAuthenticationValidator(
                        redirectValidator.andThen(
                                OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_SCOPE_VALIDATOR));
            }
        });
    }

    /**
     * Everything else: sign-in with the configured identity providers (Google and GitHub) and health.
     * The custom /login page is served from static/login.html; provider links still use Spring's
     * standard /oauth2/authorization/{registrationId} endpoints.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          FederatedLoginSuccessHandler successHandler,
                                                          LogoutRedirectHandler logoutHandler,
                                                          GitHubOAuth2UserService githubOAuth2UserService) throws Exception {
        http
                .csrf(csrf -> csrf.ignoringRequestMatchers(new AntPathRequestMatcher("/oauth2/register", "POST")))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health/**", "/actuator/prometheus", "/error", "/login", "/login.html", "/oauth2/register").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(login -> login
                        .loginPage("/login")
                        .userInfoEndpoint(userInfo -> userInfo.userService(githubOAuth2UserService))
                        .successHandler(successHandler))
                // GET /logout?redirect=<allow-listed url> ends this server's sign-in session, so "sign out" in an
                // app really signs the person out instead of silently signing them back in.
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessHandler(logoutHandler)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID"));
        return http.build();
    }
}