package org.keycloak.resource.bridge;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.testcontainers.containers.Network;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
public class BridgeResourceProviderIT {
    private static final String TEST_REALM = "test-realm";
    private static final String TEST_USER = "test-user";
    private static final String TEST_PASSWORD = "test-password";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Network network = Network.newNetwork();

    @SuppressWarnings("resource")
    @Container
    private static final KeycloakContainer keycloakContainer = new KeycloakContainer("quay.io/keycloak/keycloak:26.1.4")
            .withAdminUsername("admin")
            .withAdminPassword("admin")
            .withRealmImportFile("test-realm.json")
            .withCopyFileToContainer(
                    MountableFile.forHostPath("target/keycloak-postgresql-user-storage-spi-1.0.0-jar-with-dependencies.jar"),
                    "/opt/keycloak/providers/keycloak-postgresql-user-storage-spi-1.0.0-jar-with-dependencies.jar"
            )
            .withEnv("KC_SPI_PROVIDERS", "classpath:/providers/")
            .withNetwork(network)
            .withNetworkAliases("keycloak")
            .withEnv("KC_HOSTNAME_STRICT", "false")
            .withEnv("KC_PROXY_HEADERS", "xforwarded") // Make Keycloak _think_ it is behind a L7 proxy
            .withLogConsumer(outputFrame -> System.out.print(outputFrame.getUtf8String()));

    private static Keycloak adminClient;
    private static Client httpClient;

    @BeforeAll
    static void setup() {
        // Start container
        keycloakContainer.start();

        // Initialize admin client using the container's built-in method
        adminClient = keycloakContainer.getKeycloakAdminClient();

        // Create a JAX-RS client for making direct requests to the bridge endpoint
        httpClient = ClientBuilder.newClient().register(new XForwardedForFilter());

        // Create test user if not exists
        createTestUserIfNotExists();
    }

    @AfterAll
    static void cleanup() {
        if (httpClient != null) {
            httpClient.close();
        }
        keycloakContainer.stop();
    }

    @Test
    void testBridgeTokenEndpoint() throws Exception {
        // Build the bridge token endpoint URL
        String bridgeEndpointUrl = keycloakContainer.getAuthServerUrl() + "/realms/" + TEST_REALM + "/bridge/token";
        System.out.println("External Bridge URL: " + bridgeEndpointUrl);

        // Prepare the credentials payload
        Map<String, String> credentials = new HashMap<>();
        credentials.put("username", TEST_USER);
        credentials.put("password", TEST_PASSWORD);

        // Send request to the bridge token endpoint
        WebTarget target = httpClient.target(bridgeEndpointUrl);
        Response response = target
                .request(MediaType.APPLICATION_JSON_TYPE)
                .post(Entity.json(MAPPER.writeValueAsString(credentials)));

        // Assert the response is successful
        assertEquals(200, response.getStatus(), "Bridge token endpoint should return 200 OK");

        // Parse the response body
        String responseBody = response.readEntity(String.class);
        JsonNode responseJson = MAPPER.readTree(responseBody);

        // Assert the response contains expected OAuth tokens
        assertTrue(responseJson.has("access_token"), "Response should contain access_token");
        assertTrue(responseJson.has("refresh_token"), "Response should contain refresh_token");
        assertTrue(responseJson.has("token_type"), "Response should contain token_type");
        assertEquals("Bearer", responseJson.get("token_type").asText(), "Token type should be Bearer");
    }

    @Test
    void testBridgeTokenEndpointWithInvalidCredentials() throws Exception {
        // Build the bridge token endpoint URL
        String bridgeEndpointUrl = keycloakContainer.getAuthServerUrl() + "/realms/" + TEST_REALM + "/bridge/token";

        // Prepare invalid credentials payload
        Map<String, String> invalidCredentials = new HashMap<>();
        invalidCredentials.put("username", TEST_USER);
        invalidCredentials.put("password", "wrong-password");

        // Send request to the bridge token endpoint
        WebTarget target = httpClient.target(bridgeEndpointUrl);
        Response response = target
                .request(MediaType.APPLICATION_JSON_TYPE)
                .post(Entity.json(MAPPER.writeValueAsString(invalidCredentials)));

        // Assert the response has the expected error status
        assertEquals(401, response.getStatus(), "Bridge token endpoint should return 401 for invalid credentials");

        // Parse the response body
        String responseBody = response.readEntity(String.class);
        JsonNode responseJson = MAPPER.readTree(responseBody);

        // Assert the response contains the expected error information
        assertTrue(responseJson.has("error"), "Response should contain error field");
        assertEquals("invalid_grant", responseJson.get("error").asText(), "Error should be invalid_grant");
    }

    @Test
    void testBridgeTokenEndpointWithMissingCredentials() throws Exception {
        // Build the bridge token endpoint URL
        String bridgeEndpointUrl = keycloakContainer.getAuthServerUrl() + "/realms/" + TEST_REALM + "/bridge/token";

        // Prepare incomplete credentials payload
        Map<String, String> incompleteCredentials = new HashMap<>();
        incompleteCredentials.put("username", TEST_USER);
        // Missing password field

        // Send request to the bridge token endpoint
        WebTarget target = httpClient.target(bridgeEndpointUrl);
        Response response = target
                .request(MediaType.APPLICATION_JSON_TYPE)
                .post(Entity.json(MAPPER.writeValueAsString(incompleteCredentials)));

        // Assert the response has the expected error status
        assertEquals(400, response.getStatus(), "Bridge token endpoint should return 400 for missing credentials");

        // Parse the response body
        String responseBody = response.readEntity(String.class);
        JsonNode responseJson = MAPPER.readTree(responseBody);

        // Assert the response contains the expected error information
        assertTrue(responseJson.has("error"), "Response should contain error field");
        assertEquals("invalid_request", responseJson.get("error").asText(), "Error should be invalid_request");
    }

    private static void createTestUserIfNotExists() {
        RealmResource realmResource = adminClient.realm(TEST_REALM);

        // Check if user already exists
        if (realmResource.users().search(TEST_USER).isEmpty()) {
            // Create a test user in the test realm
            org.keycloak.representations.idm.UserRepresentation user = new org.keycloak.representations.idm.UserRepresentation();
            user.setUsername(TEST_USER);
            user.setEnabled(true);
            user.setEmailVerified(true);

            try (Response response = realmResource.users().create(user)) {
                assertEquals(201, response.getStatus(), "User creation should succeed");

                // Extract the user ID from the response
                String userId = extractCreatedId(response);

                // Set password for the user
                org.keycloak.representations.idm.CredentialRepresentation credential = new org.keycloak.representations.idm.CredentialRepresentation();
                credential.setType(org.keycloak.representations.idm.CredentialRepresentation.PASSWORD);
                credential.setValue(TEST_PASSWORD);
                credential.setTemporary(false);

                realmResource.users().get(userId).resetPassword(credential);
            }
        }
    }

    private static String extractCreatedId(Response response) {
        String location = response.getHeaderString("Location");
        return location.substring(location.lastIndexOf("/") + 1);
    }

    /**
     * A filter for our IT HTTP client to add X-Forwarded-* headers to the request.
     *
     * Why do we need this? In summary, Keycloak enforces a way of dealing with forwarded requests, and
     * since our testcontainer is essentially reverse proxied (through port mapping) by Docker to the host
     * we have to tweak the request to make it look like it is coming from a L7 proxy and behave the way
     * we need.
     */
    private static class XForwardedForFilter implements ClientRequestFilter {
        @Override
        public void filter(ClientRequestContext requestContext) throws IOException {
            requestContext.getHeaders().add("X-Forwarded-Host", "keycloak");
            requestContext.getHeaders().add("X-Forwarded-Proto", "http");
            requestContext.getHeaders().add("X-Forwarded-Port", "8080");
        }
    }
}
