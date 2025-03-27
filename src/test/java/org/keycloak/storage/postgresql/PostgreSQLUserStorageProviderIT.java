package org.keycloak.storage.postgresql;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import jakarta.ws.rs.core.Response;
import org.keycloak.common.util.MultivaluedHashMap;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
public class PostgreSQLUserStorageProviderIT {

    private static final String TEST_REALM = "test-realm";
    private static final String TEST_CLIENT = "test-client";
    private static final String TEST_CLIENT_SECRET = "test-client-secret";
    private static final String TEST_USER_EMAIL = "testuser@example.com";
    private static final String TEST_PASSWORD = "testpassword";

    // Create shared network for containers
    private static final Network SHARED_NETWORK = Network.newNetwork();

    @SuppressWarnings("resource")
    @Container
    private static final PostgreSQLContainer<?> postgreSQLContainer = new PostgreSQLContainer<>("postgres:16")
            .withDatabaseName("keycloak_test")
            .withUsername("keycloak")
            .withPassword("keycloak")
            .withNetwork(SHARED_NETWORK)
            .withNetworkAliases("postgres");

    @SuppressWarnings("resource")
    @Container
    private static final KeycloakContainer keycloakContainer = new KeycloakContainer("quay.io/keycloak/keycloak:26.1.4")
            .withAdminUsername("myKeycloakAdminUser")
            .withAdminPassword("tops3cr3t")
            .withRealmImportFile("test-realm.json")
            .withCopyFileToContainer(
                    MountableFile.forHostPath("target/keycloak-postgresql-user-storage-spi-1.0.0-jar-with-dependencies.jar"),
                    "/opt/keycloak/providers/keycloak-postgresql-user-storage-spi-1.0.0-jar-with-dependencies.jar"
            )
            .withEnv("KC_SPI_PROVIDERS", "classpath:/providers/")
            .withNetwork(SHARED_NETWORK)
            .withNetworkAliases("keycloak")
            .dependsOn(postgreSQLContainer)
            .withStartupTimeout(Duration.ofMinutes(2)) // Increase timeout to 2 minutes
            .withLogConsumer(outputFrame -> System.out.print(outputFrame.getUtf8String()));

    private static Keycloak adminClient;
    private static String componentId;

    @BeforeAll
    static void setup() throws SQLException {
        // Start containers
        postgreSQLContainer.start();
        keycloakContainer.start();

        // Initialize admin client using the container's built-in method
        adminClient = keycloakContainer.getKeycloakAdminClient();

        // Create test users in PostgreSQL
        setupTestDatabase();

        // Configure user federation provider
        setupUserFederationProvider();
    }

    @AfterAll
    static void cleanup() {
        keycloakContainer.stop();
        postgreSQLContainer.stop();
    }

    @Test
    void testUserLookup() {
        RealmResource realmResource = adminClient.realm(TEST_REALM);
        List<UserRepresentation> users = realmResource.users().search(TEST_USER_EMAIL, 0, 1);

        assertFalse(users.isEmpty(), "Test user should be found via federation");
        assertEquals(TEST_USER_EMAIL, users.get(0).getUsername(), "Username should match the email");
        assertEquals(TEST_USER_EMAIL, users.get(0).getEmail(), "Email should match");
    }

    @Test
    void testUserAuthentication() {
        try {
            // Test direct grant login for the federated user with email as username
            Keycloak userClient = Keycloak.getInstance(
                    keycloakContainer.getAuthServerUrl(),
                    TEST_REALM,
                    TEST_USER_EMAIL,
                    TEST_PASSWORD,
                    TEST_CLIENT,
                    TEST_CLIENT_SECRET
            );

            assertNotNull(userClient.tokenManager().getAccessToken(), "Should receive valid access token");
            userClient.close();
        } catch (Exception e) {
            System.err.println("Authentication failed: " + e.getMessage());
            e.printStackTrace();
            fail("Authentication failed: " + e.getMessage());
        }
    }

    @Test
    void testUserImportedAfterFirstLogin() {
        // First, authenticate the user
        Keycloak userClient = Keycloak.getInstance(
                keycloakContainer.getAuthServerUrl(),
                TEST_REALM,
                TEST_USER_EMAIL,
                TEST_PASSWORD,
                TEST_CLIENT,
                TEST_CLIENT_SECRET
        );
        userClient.tokenManager().getAccessToken();
        userClient.close();

        // Then, verify the user was imported and exists in local storage
        RealmResource realmResource = adminClient.realm(TEST_REALM);
        List<UserRepresentation> users = realmResource.users().search(TEST_USER_EMAIL, 0, 1);

        assertFalse(users.isEmpty(), "User should exist in local storage after login");
        UserRepresentation user = users.get(0);

        // Verify federation link
        UserResource userResource = realmResource.users().get(user.getId());
        UserRepresentation userWithAttributes = userResource.toRepresentation();

        // The federation link should match our component id
        assertEquals(componentId, userWithAttributes.getFederationLink(),
                "User should have federation link to our provider");
    }

    private static void setupTestDatabase() throws SQLException {
        try (Connection conn = DriverManager.getConnection(
                postgreSQLContainer.getJdbcUrl(),
                postgreSQLContainer.getUsername(),
                postgreSQLContainer.getPassword())) {

            // Create users table
            conn.createStatement().execute(
                    "CREATE TABLE IF NOT EXISTS users (" +
                    "  id UUID PRIMARY KEY," +
                    "  email VARCHAR(255) NOT NULL UNIQUE," +
                    "  first_name VARCHAR(255)," +
                    "  last_name VARCHAR(255)," +
                    "  password_digest VARCHAR(255) NOT NULL" +
                    ")"
            );

            // Insert a test user with bcrypt password hash for 'testpassword'
            String bcryptHash = "$2y$12$cKlMe72KCTF6iMVk2SIFpegWs3tvq3.GwrhAXRKOmh16GIzOuR7Sq";

            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO users (id, email, first_name, last_name, password_digest) " +
                    "VALUES (?, ?, ?, ?, ?)")) {
                ps.setObject(1, UUID.randomUUID());
                ps.setString(2, TEST_USER_EMAIL);
                ps.setString(3, "Test");
                ps.setString(4, "User");
                ps.setString(5, bcryptHash);
                ps.executeUpdate();
            }
        }
    }

    private static void setupUserFederationProvider() {
        RealmResource realmResource = adminClient.realm(TEST_REALM);

        // Create user federation provider component
        ComponentRepresentation postgresProvider = new ComponentRepresentation();
        postgresProvider.setName("postgres-provider");
        postgresProvider.setProviderId(PostgreSQLUserStorageProviderFactory.PROVIDER_ID);
        postgresProvider.setProviderType("org.keycloak.storage.UserStorageProvider");

        // Set configuration
        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        String jdbcUrl = String.format("jdbc:postgresql://postgres:%d/%s",
                            PostgreSQLContainer.POSTGRESQL_PORT,
                            postgreSQLContainer.getDatabaseName());

        System.out.println("Setting JDBC URL for federation provider: " + jdbcUrl);

        config.putSingle("jdbcUrl", jdbcUrl);
        config.putSingle("username", postgreSQLContainer.getUsername());
        config.putSingle("password", postgreSQLContainer.getPassword());
        config.putSingle("importUsers",  "true");

        postgresProvider.setConfig(config);

        // Create the component and store its ID
        try (Response response = realmResource.components().add(postgresProvider)) {
            componentId = createdId(response);
        }
    }

    private static String createdId(Response response) {
        if (response.getStatus() == 201) {
            String location = response.getHeaderString("Location");
            return location.substring(location.lastIndexOf("/") + 1);
        }
        return null;
    }
}
