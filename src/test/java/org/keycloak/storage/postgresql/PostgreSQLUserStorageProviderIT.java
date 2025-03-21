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
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import jakarta.ws.rs.core.Response;
import org.keycloak.common.util.MultivaluedHashMap;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
public class PostgreSQLUserStorageProviderIT {

    private static final String TEST_REALM = "test-realm";
    private static final String TEST_CLIENT = "test-client";
    private static final String TEST_USER = "testuser";
    private static final String TEST_PASSWORD = "testpassword";
    
    @SuppressWarnings("resource")
    @Container
    private static final PostgreSQLContainer<?> postgreSQLContainer = new PostgreSQLContainer<>("postgres:16")
            .withDatabaseName("keycloak_test")
            .withUsername("keycloak")
            .withPassword("keycloak");

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
        List<UserRepresentation> users = realmResource.users().search(TEST_USER, 0, 1);
        
        assertFalse(users.isEmpty(), "Test user should be found via federation");
        assertEquals(TEST_USER, users.get(0).getUsername(), "Username should match");
    }
    
    @Test
    void testUserAuthentication() {
        // Test direct grant login for the federated user
        Keycloak userClient = Keycloak.getInstance(
                keycloakContainer.getAuthServerUrl(),
                TEST_REALM,
                TEST_USER,
                TEST_PASSWORD,
                TEST_CLIENT
        );
        
        assertNotNull(userClient.tokenManager().getAccessToken(), "Should receive valid access token");
        userClient.close();
    }
    
    @Test
    void testUserImportedAfterFirstLogin() {
        // First, authenticate the user
        Keycloak userClient = Keycloak.getInstance(
                keycloakContainer.getAuthServerUrl(),
                TEST_REALM,
                TEST_USER,
                TEST_PASSWORD,
                TEST_CLIENT
        );
        userClient.tokenManager().getAccessToken();
        userClient.close();
        
        // Then, verify the user was imported and exists in local storage
        RealmResource realmResource = adminClient.realm(TEST_REALM);
        List<UserRepresentation> users = realmResource.users().search(TEST_USER, 0, 1);
        
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
                    "  id VARCHAR(36) PRIMARY KEY," +
                    "  username VARCHAR(255) NOT NULL UNIQUE," +
                    "  email VARCHAR(255)," +
                    "  first_name VARCHAR(255)," +
                    "  last_name VARCHAR(255)," +
                    "  password_hash VARCHAR(255) NOT NULL," +
                    "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                    ")"
            );
            
            // Insert a test user with bcrypt password hash for 'testpassword'
            // Note: In a real implementation, generate this properly
            String bcryptHash = "$2a$10$x.1AY/ovrVpR4QgFiZZ64.YPyJX2rXg8jP5PyDLD4lATAPlsVIB1W"; 
            
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO users (id, username, email, first_name, last_name, password_hash) " +
                    "VALUES (?, ?, ?, ?, ?, ?)")) {
                ps.setString(1, UUID.randomUUID().toString());
                ps.setString(2, TEST_USER);
                ps.setString(3, TEST_USER + "@example.com");
                ps.setString(4, "Test");
                ps.setString(5, "User");
                ps.setString(6, bcryptHash);
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
        config.putSingle("jdbcUrl", postgreSQLContainer.getJdbcUrl());
        config.putSingle("username", postgreSQLContainer.getUsername());
        config.putSingle("password", postgreSQLContainer.getPassword());
        config.putSingle("usersTable", "users");
        config.putSingle("usernameColumn", "username");
        config.putSingle("emailColumn", "email");
        config.putSingle("firstNameColumn", "first_name");
        config.putSingle("lastNameColumn", "last_name");
        config.putSingle("passwordColumn", "password_hash");

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
