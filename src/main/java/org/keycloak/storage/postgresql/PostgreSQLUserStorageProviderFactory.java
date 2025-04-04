package org.keycloak.storage.postgresql;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

/**
 * Factory for PostgreSQL User Storage Provider
 */
public class PostgreSQLUserStorageProviderFactory implements UserStorageProviderFactory<PostgreSQLUserStorageProvider> {

    public static final String PROVIDER_ID = "postgresql-user-storage";

    public static final String JDBC_URL = "jdbcUrl";
    public static final String DB_USERNAME = "username";
    public static final String DB_PASSWORD = "password";
    public static final String IMPORT_USERS = "importUsers";

    private static final String USERS_TABLE_NAME = "users";
    private static final Logger logger = LoggerFactory.getLogger(PostgreSQLUserStorageProviderFactory.class);

    protected static final List<ProviderConfigProperty> configMetadata;

    static {
        configMetadata = ProviderConfigurationBuilder.create()
            .property()
                .name(JDBC_URL)
                .label("JDBC URL")
                .helpText("JDBC URL for connecting to the PostgreSQL database (e.g., jdbc:postgresql://localhost:5432/mydb)")
                .type(ProviderConfigProperty.STRING_TYPE)
                .required(true)
                .add()
            .property()
                .name(DB_USERNAME)
                .label("Database Username")
                .helpText("Username for authenticating to the PostgreSQL database")
                .type(ProviderConfigProperty.STRING_TYPE)
                .required(true)
                .add()
            .property()
                .name(DB_PASSWORD)
                .label("Database Password")
                .helpText("Password for authenticating to the PostgreSQL database")
                .type(ProviderConfigProperty.PASSWORD)
                .required(true)
                .secret(true)
                .add()
            .property()
                .name(IMPORT_USERS)
                .label("Import Users")
                .helpText("Flag to enable importing users into Keycloak's database")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
            .build();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configMetadata;
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {
        String jdbcUrl = config.getConfig().getFirst(JDBC_URL);
        String username = config.getConfig().getFirst(DB_USERNAME);
        String password = config.getConfig().getFirst(DB_PASSWORD);

        if (jdbcUrl == null || jdbcUrl.trim().isEmpty()) {
            throw new ComponentValidationException("JDBC URL is required");
        }

        if (username == null || username.trim().isEmpty()) {
            throw new ComponentValidationException("Database username is required");
        }

        if (password == null || password.trim().isEmpty()) {
            throw new ComponentValidationException("Database password is required");
        }

        // Test the database connection
        PostgreSQLConnectionManager connectionManager = getConnectionManager(config);
        try (Connection conn = connectionManager.getConnection()) {
            logger.info("Successfully established connection to PostgreSQL database");
        } catch (SQLException e) {
            logger.error("Failed to establish connection to PostgreSQL database", e);
            throw new ComponentValidationException("Failed to connect to PostgreSQL database: " + e.getMessage(), e);
        }
    }

    @Override
    public PostgreSQLUserStorageProvider create(KeycloakSession session, ComponentModel model) {
        PostgreSQLConnectionManager connectionManager = getConnectionManager(model);
        boolean importUsers = Boolean.parseBoolean(model.getConfig().getFirst(IMPORT_USERS));
        return new PostgreSQLUserStorageProvider(session, model, connectionManager, importUsers);
    }

    @Override
    public void init(Config.Scope config) {
        try {
            Class.forName("org.postgresql.Driver");
            logger.info("PostgreSQL JDBC driver loaded successfully");
        } catch (ClassNotFoundException e) {
            logger.error("Failed to load PostgreSQL JDBC driver", e);
            throw new RuntimeException("Failed to load PostgreSQL JDBC driver", e);
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // NO-OP
    }

    @Override
    public void close() {
        // NO-OP
    }

    private PostgreSQLConnectionManager getConnectionManager(ComponentModel config) {
        String jdbcUrl = config.getConfig().getFirst(JDBC_URL);
        String username = config.getConfig().getFirst(DB_USERNAME);
        String password = config.getConfig().getFirst(DB_PASSWORD);

        return new PostgreSQLConnectionManager(
            jdbcUrl,
            username,
            password,
            USERS_TABLE_NAME
        );
    }
}
