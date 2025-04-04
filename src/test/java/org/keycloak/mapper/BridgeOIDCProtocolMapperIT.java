package org.keycloak.mapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.TokenVerifier;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;

@Testcontainers
public class BridgeOIDCProtocolMapperIT {

    private static final String TEST_REALM = "test-realm";
    private static final String TEST_CLIENT = "test-client";
    private static final String TEST_CLIENT_SECRET = "test-client-secret";
    private static final String TEST_USER = "bridge-test@example.com"; // See test-realm.json
    private static final String TEST_USER_PASSWORD = "test-password"; // See test-realm.json

    // Test data for federated attributes
    private static final String TEST_BUSINESS_NAME = "Test Business";
    private static final String TEST_USER_CODE = "USER123";
    private static final String TEST_BUSINESS_TYPE = "Corporation";
    private static final String TEST_ROLE = "admin";

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
            .withStartupTimeout(Duration.ofMinutes(2))
            .withLogConsumer(outputFrame -> System.out.print(outputFrame.getUtf8String()));

    private static Keycloak adminClient;
    private static Client httpClient;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @BeforeAll
    static void setup() {
        // Start container
        keycloakContainer.start();

        // Initialize admin client using the container's built-in method
        adminClient = keycloakContainer.getKeycloakAdminClient();

        // Create a JAX-RS client for making direct requests
        httpClient = ClientBuilder.newClient();

        // Setup Bridge OIDC Protocol Mapper
        setupBridgeOIDCMapper(adminClient.realm(TEST_REALM));

    }

    @AfterAll
    static void cleanup() {
        if (httpClient != null) {
            httpClient.close();
        }
        keycloakContainer.stop();
    }

    @Test
    void testBridgeMapperInIDToken() throws Exception {
        // Get an access token for the test user
        AccessTokenResponse tokenResponse = getAccessToken();
        assertNotNull(tokenResponse, "Should receive valid token response");

        // Verify ID token presence and content
        String idToken = tokenResponse.getIdToken();
        assertNotNull(idToken, "ID token should not be null");

        // Continue with ID token verification
        TokenVerifier<IDToken> verifier = TokenVerifier.create(idToken, IDToken.class);
        verifier.parse();
        IDToken token = verifier.getToken();

        // Verify the expected claims
        assertNotNull(token.getOtherClaims().get("businessName"), "businessName claim should be present");
        assertEquals(TEST_BUSINESS_NAME, token.getOtherClaims().get("businessName").toString());

        assertNotNull(token.getOtherClaims().get("userCode") , "userCode claim should be present");
        assertEquals(TEST_USER_CODE, token.getOtherClaims().get("userCode").toString());

        assertNotNull(token.getOtherClaims().get("businessType") , "businessType claim should be present");
        assertEquals(TEST_BUSINESS_TYPE, token.getOtherClaims().get("businessType").toString());

        assertNotNull(token.getOtherClaims().get("role") , "role claim should be present");
        assertEquals(TEST_ROLE, token.getOtherClaims().get("role").toString());

        assertNull(token.getOtherClaims().get("origin"), "origin claim should not be present, doesn't have the FED prefix");
    }

    @Test
    void testBridgeMapperInUserInfo() throws Exception {
        // Get an access token for the test user
        AccessTokenResponse tokenResponse = getAccessToken();
        assertNotNull(tokenResponse, "Should receive valid token response");

        // Use the access token to request the UserInfo endpoint
        String userInfoEndpointUrl = keycloakContainer.getAuthServerUrl() + "/realms/" + TEST_REALM + "/protocol/openid-connect/userinfo";
        WebTarget userInfoTarget = httpClient.target(userInfoEndpointUrl);

        Response userInfoResponse = userInfoTarget
                .request()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenResponse.getToken())
                .get();

        assertEquals(200, userInfoResponse.getStatus(), "UserInfo endpoint should return 200 OK");

        // Parse the response body
        String responseBody = userInfoResponse.readEntity(String.class);
        JsonNode userInfoJson = MAPPER.readTree(responseBody);

        // Verify that the bridge mapped claims are present in the UserInfo response
        assertTrue(userInfoJson.has("businessName"), "businessName claim should be present");
        assertEquals(TEST_BUSINESS_NAME, userInfoJson.get("businessName").asText());

        assertTrue(userInfoJson.has("userCode"), "userCode claim should be present");
        assertEquals(TEST_USER_CODE, userInfoJson.get("userCode").asText());

        assertTrue(userInfoJson.has("businessType"), "businessType claim should be present");
        assertEquals(TEST_BUSINESS_TYPE, userInfoJson.get("businessType").asText());

        assertTrue(userInfoJson.has("role"), "role claim should be present");
        assertEquals(TEST_ROLE, userInfoJson.get("role").asText());

        assertTrue(!userInfoJson.has("origin"), "origin claim should not be present, doesn't have the FED prefix");
    }

    /**
     * Get an access token for the test user
     */
    private AccessTokenResponse getAccessToken() {
        try {
            KeycloakBuilder builder = KeycloakBuilder.builder()
                    .serverUrl(keycloakContainer.getAuthServerUrl())
                    .realm(TEST_REALM)
                    .clientId(TEST_CLIENT)
                    .clientSecret(TEST_CLIENT_SECRET)
                    .username(TEST_USER)
                    .password(TEST_USER_PASSWORD)
                    .grantType("password")
                    .scope("openid");

            return builder.build().tokenManager().getAccessToken();
        } catch (Exception e) {
            fail("Failed to get access token: " + e.getMessage());
            return null;
        }
    }

	private static void setupBridgeOIDCMapper(RealmResource realm) {
        ClientRepresentation client = realm.clients().findByClientId(TEST_CLIENT).get(0);
        String clientId = client.getId();

        ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
        mapper.setName("bridge-oidc-mapper");
        mapper.setProtocolMapper(BridgeOIDCProtocolMapper.PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);

        Map<String, String> config = new HashMap<>();
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "true");
        mapper.setConfig(config);

        realm.clients().get(clientId).getProtocolMappers().createMapper(mapper);
	}

    /**
     * Debug helper to decode and print token contents.
     *
     * NOTE: Keep this method even if not used in the tests, as it can be useful for debugging.
     */
    @SuppressWarnings("unused")
    private void debugToken(String tokenType, String token) {
        if (token == null) {
            System.out.println("\n" + tokenType + ": null");
            return;
        }

        System.out.println("\n" + tokenType + " Details:");
        String[] tokenParts = token.split("\\.");
        if (tokenParts.length > 1) {
            String header = new String(Base64.getUrlDecoder().decode(tokenParts[0]));
            String payload = new String(Base64.getUrlDecoder().decode(tokenParts[1]));

            System.out.println("  Header: " + header);
            System.out.println("  Payload: " + payload);

            try {
                // Parse the JSON payload to inspect claims
                ObjectMapper mapper = new ObjectMapper();
                JsonNode payloadJson = mapper.readTree(payload);

                System.out.println("\n  Claims:");
                payloadJson.fields().forEachRemaining(entry ->
                    System.out.println("    " + entry.getKey() + " = " + entry.getValue()));
            } catch (Exception e) {
                System.out.println("  Error parsing token JSON: " + e.getMessage());
            }
        } else {
            System.out.println("  Invalid token format");
        }
    }
}
