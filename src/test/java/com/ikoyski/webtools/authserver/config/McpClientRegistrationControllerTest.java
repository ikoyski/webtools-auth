package com.ikoyski.webtools.authserver.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@ExtendWith(MockitoExtension.class)
class McpClientRegistrationControllerTest {

    private static final String MCP_RESOURCE = "https://api.example.test/kanban-mcp/mcp";
    private static final String BACKEND_RESOURCE = "https://api.example.test/kanban-backend";
    private static final String HOMELAB_RESOURCE = "https://homelab-mcp.example.test/mcp";

    @Mock
    private RegisteredClientRepository clients;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Test
    void registersPublicPkceClientForCursorCallback() {
        McpClientRegistrationController controller = controller(true);
        Map<String, Object> request = Map.of(
                "client_name", "Cursor",
                "redirect_uris", List.of("https://www.cursor.com/agents/mcp/oauth/callback"),
                "grant_types", List.of("authorization_code"),
                "response_types", List.of("code"),
                "token_endpoint_auth_method", "none",
                "scope", "kanban.read kanban.write");

        ResponseEntity<Map<String, Object>> response = controller.register(request);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertNotNull(response.getBody().get("client_id"));
        assertNull(response.getBody().get("client_secret"));
        assertEquals("none", response.getBody().get("token_endpoint_auth_method"));

        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(clients).save(captor.capture());
        RegisteredClient registered = captor.getValue();
        assertEquals(ClientAuthenticationMethod.NONE, registered.getClientAuthenticationMethods().iterator().next());
        assertTrue(registered.getClientSettings().isRequireProofKey());
        assertTrue(registered.getClientSettings().isRequireAuthorizationConsent());
        assertEquals(Set.of("kanban.read", "kanban.write"), registered.getScopes());
        assertEquals(Set.of(AuthorizationGrantType.AUTHORIZATION_CODE), registered.getAuthorizationGrantTypes());
        assertEquals(Set.of("https://www.cursor.com/agents/mcp/oauth/callback"), registered.getRedirectUris());
        assertEquals(MCP_RESOURCE, registered.getClientSettings().getSetting(ClientSeeder.MCP_RESOURCE_SETTING));
        assertEquals(BACKEND_RESOURCE,
                registered.getClientSettings().getSetting(ClientSeeder.MCP_BACKEND_RESOURCE_SETTING));
    }

    @Test
    void registersGrokAsConfidentialClientWithOneTimeGeneratedSecret() {
        McpClientRegistrationController controller = controller(true);
        Map<String, Object> request = Map.of(
                "client_name", "Grok Kanban",
                "redirect_uris", List.of("https://grok.com/connectors-oauth-exchange-code/"),
                "grant_types", List.of("authorization_code"),
                "response_types", List.of("code"),
                "token_endpoint_auth_method", "client_secret_post",
                "scope", "kanban.read kanban.write");

        ResponseEntity<Map<String, Object>> response = controller.register(request);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertNotNull(response.getBody());
        String clientSecret = (String) response.getBody().get("client_secret");
        assertNotNull(clientSecret);
        assertEquals(0, response.getBody().get("client_secret_expires_at"));
        assertEquals("client_secret_post", response.getBody().get("token_endpoint_auth_method"));

        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(clients).save(captor.capture());
        RegisteredClient registered = captor.getValue();
        assertEquals(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_POST),
                registered.getClientAuthenticationMethods());
        assertNotNull(registered.getClientSecret());
        assertTrue(passwordEncoder.matches(clientSecret, registered.getClientSecret()));
        assertTrue(registered.getClientSettings().isRequireProofKey());
        assertTrue(registered.getClientSettings().isRequireAuthorizationConsent());
        assertEquals(Set.of("kanban.read", "kanban.write"), registered.getScopes());
    }

    @Test
    void registersHomelabClientWithOnlyTheHomelabAudience() {
        McpClientRegistrationController controller = controller(true);
        Map<String, Object> request = Map.of(
                "client_name", "Homelab MCP",
                "redirect_uris", List.of("https://claude.ai/api/mcp/auth_callback"),
                "grant_types", List.of("authorization_code"),
                "response_types", List.of("code"),
                "token_endpoint_auth_method", "none",
                "scope", "homelab.read");

        ResponseEntity<Map<String, Object>> response = controller.register(request);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(clients).save(captor.capture());
        RegisteredClient registered = captor.getValue();
        assertEquals(Set.of("homelab.read"), registered.getScopes());
        assertEquals(HOMELAB_RESOURCE,
                registered.getClientSettings().getSetting(ClientSeeder.MCP_RESOURCE_SETTING));
        assertNull(registered.getClientSettings().getSetting(ClientSeeder.MCP_BACKEND_RESOURCE_SETTING));
    }


    @Test
    void rejectsRefreshTokenGrantAndOfflineAccessScope() {
        McpClientRegistrationController controller = controller(true);
        Map<String, Object> refreshGrantRequest = Map.of(
                "redirect_uris", List.of("https://www.cursor.com/agents/mcp/oauth/callback"),
                "grant_types", List.of("authorization_code", "refresh_token"),
                "scope", "kanban.read");
        Map<String, Object> offlineScopeRequest = Map.of(
                "redirect_uris", List.of("https://www.cursor.com/agents/mcp/oauth/callback"),
                "scope", "kanban.read offline_access");

        assertEquals(HttpStatus.BAD_REQUEST, controller.register(refreshGrantRequest).getStatusCode());
        assertEquals(HttpStatus.BAD_REQUEST, controller.register(offlineScopeRequest).getStatusCode());
        verify(clients, never()).save(any());
    }

    @Test
    void rejectsMixedHomelabAndKanbanScopes() {
        McpClientRegistrationController controller = controller(true);
        Map<String, Object> request = Map.of(
                "redirect_uris", List.of("https://claude.ai/api/mcp/auth_callback"),
                "scope", "homelab.read kanban.read");

        ResponseEntity<Map<String, Object>> response = controller.register(request);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        verify(clients, never()).save(any());
    }

    @Test
    void registersGeminiHomelabCallbackAsDynamicRedirectClient() {
        McpClientRegistrationController controller = controller(true);
        Map<String, Object> request = Map.of(
                "client_name", "Gemini Homelab",
                "redirect_uris", List.of("https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-123"),
                "scope", "homelab.read");

        ResponseEntity<Map<String, Object>> response = controller.register(request);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(clients).save(captor.capture());
        RegisteredClient registered = captor.getValue();
        assertEquals(HOMELAB_RESOURCE,
                registered.getClientSettings().getSetting(ClientSeeder.MCP_RESOURCE_SETTING));
        assertEquals(Boolean.TRUE,
                registered.getClientSettings().getSetting(ClientSeeder.GEMINI_DYNAMIC_REDIRECT_SETTING));
    }

    @Test
    void rejectsClientSecretPostForNonGrokCallback() {
        McpClientRegistrationController controller = controller(true);
        Map<String, Object> request = Map.of(
                "redirect_uris", List.of("https://www.cursor.com/agents/mcp/oauth/callback"),
                "token_endpoint_auth_method", "client_secret_post");

        ResponseEntity<Map<String, Object>> response = controller.register(request);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        verify(clients, never()).save(any());
    }

    @Test
    void rejectsUnapprovedRedirectUris() {
        McpClientRegistrationController controller = controller(true);
        Map<String, Object> request = Map.of(
                "redirect_uris", List.of("https://attacker.example/callback"));

        ResponseEntity<Map<String, Object>> response = controller.register(request);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("invalid_client_metadata", response.getBody().get("error"));
        verify(clients, never()).save(any());
    }

    @Test
    void rejectsClientSuppliedSecrets() {
        McpClientRegistrationController controller = controller(true);
        Map<String, Object> request = Map.of(
                "redirect_uris", List.of("https://grok.com/connectors-oauth-exchange-code/"),
                "client_secret", "must-not-be-accepted");

        ResponseEntity<Map<String, Object>> response = controller.register(request);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        verify(clients, never()).save(any());
    }

    @Test
    void rejectsScopesOutsideKanbanMcpPermissions() {
        McpClientRegistrationController controller = controller(true);
        Map<String, Object> request = Map.of(
                "redirect_uris", List.of("https://grok.com/connectors-oauth-exchange-code/"),
                "scope", "kanban.read admin");

        ResponseEntity<Map<String, Object>> response = controller.register(request);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        verify(clients, never()).save(any());
    }

    @Test
    void registrationIsDisabledUnlessExplicitlyEnabled() {
        McpClientRegistrationController controller = controller(false);

        ResponseEntity<Map<String, Object>> response = controller.register(Map.of());

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        verify(clients, never()).save(any());
    }

    @Test
    void classifiesKnownTokenEndpointAuthenticationMethodsWithoutExposingUnknownValues() {
        assertEquals("omitted", McpClientRegistrationController.authenticationMethodCategory(null));
        assertEquals("none", McpClientRegistrationController.authenticationMethodCategory("none"));
        assertEquals("client_secret_basic",
                McpClientRegistrationController.authenticationMethodCategory("client_secret_basic"));
        assertEquals("client_secret_post",
                McpClientRegistrationController.authenticationMethodCategory("client_secret_post"));
        assertEquals("other",
                McpClientRegistrationController.authenticationMethodCategory("arbitrary-client-value"));
        assertEquals("invalid_type", McpClientRegistrationController.authenticationMethodCategory(42));
    }

    private McpClientRegistrationController controller(boolean enabled) {
        return new McpClientRegistrationController(
                clients, passwordEncoder, enabled, MCP_RESOURCE, BACKEND_RESOURCE, HOMELAB_RESOURCE);
    }
}
