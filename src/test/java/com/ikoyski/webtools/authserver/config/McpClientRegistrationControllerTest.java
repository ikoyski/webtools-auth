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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@ExtendWith(MockitoExtension.class)
class McpClientRegistrationControllerTest {

    private static final String MCP_RESOURCE = "https://api.example.test/kanban-mcp/mcp";
    private static final String BACKEND_RESOURCE = "https://api.example.test/kanban-backend";

    @Mock
    private RegisteredClientRepository clients;

    @Test
    void registersPublicPkceClientForGrokCallback() {
        McpClientRegistrationController controller = controller(true);
        Map<String, Object> request = Map.of(
                "client_name", "Grok Kanban",
                "redirect_uris", List.of("https://grok.com/connectors-oauth-exchange-code/"),
                "grant_types", List.of("authorization_code", "refresh_token"),
                "response_types", List.of("code"),
                "token_endpoint_auth_method", "none",
                "scope", "kanban.read kanban.write offline_access");

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
        assertEquals(Set.of("kanban.read", "kanban.write", "offline_access"), registered.getScopes());
        assertTrue(registered.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN));
        assertEquals(Set.of("https://grok.com/connectors-oauth-exchange-code/"), registered.getRedirectUris());
        assertEquals(MCP_RESOURCE, registered.getClientSettings().getSetting(ClientSeeder.MCP_RESOURCE_SETTING));
        assertEquals(BACKEND_RESOURCE,
                registered.getClientSettings().getSetting(ClientSeeder.MCP_BACKEND_RESOURCE_SETTING));
    }

    @Test
    void registersCursorDesktopAndWebCallbacks() {
        McpClientRegistrationController controller = controller(true);
        Map<String, Object> request = Map.of(
                "client_name", "Cursor",
                "redirect_uris", List.of(
                        "https://www.cursor.com/agents/mcp/oauth/callback",
                        "http://localhost:8787/callback"),
                "grant_types", List.of("authorization_code"),
                "response_types", List.of("code"),
                "token_endpoint_auth_method", "none",
                "scope", "kanban.read kanban.write");

        ResponseEntity<Map<String, Object>> response = controller.register(request);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(clients).save(captor.capture());
        assertEquals(2, captor.getValue().getRedirectUris().size());
        assertFalse(captor.getValue().getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN));
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
    void rejectsConfidentialClients() {
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

    private McpClientRegistrationController controller(boolean enabled) {
        return new McpClientRegistrationController(
                clients, enabled, MCP_RESOURCE, BACKEND_RESOURCE);
    }
}
