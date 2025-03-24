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
import org.keycloak.storage.UserStorageProviderModel;
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
    
    // Configuration properties (enables Admin UI overrides)
    public static final String JDBC_URL = "jdbcUrl";
    public static final String DB_USERNAME = "username";
    public static final String DB_PASSWORD = "password";
    public static final String USERS_TABLE = "usersTable";
    public static final String ID_FIELD = "idField"; // UUID field
    public static final String EMAIL_FIELD = "emailField"; // Used as username
    public static final String PASSWORD_FIELD = "passwordField";
    public static final String FIRSTNAME_FIELD = "firstNameField";
    public static final String LASTNAME_FIELD = "lastNameField";
    public static final String VALIDATION_QUERY = "validationQuery";
    
    // Default values (extracted from Legacy's database)
    private static final String DEFAULT_USERS_TABLE = "users";
    private static final String DEFAULT_ID_FIELD = "id";
    private static final String DEFAULT_EMAIL_FIELD = "email";
    private static final String DEFAULT_PASSWORD_FIELD = "password_digest";
    private static final String DEFAULT_FIRSTNAME_FIELD = "first_name";
    private static final String DEFAULT_LASTNAME_FIELD = "last_name";
    private static final String DEFAULT_VALIDATION_QUERY = "SELECT 1";
    
    private static final Logger logger = LoggerFactory.getLogger(PostgreSQLUserStorageProviderFactory.class);

    protected static final List<ProviderConfigProperty> configMetadata;
    
    static {
        // Configure the provider configuration properties
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
                .name(USERS_TABLE)
                .label("Users Table")
                .helpText("Name of the table that contains user information")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_USERS_TABLE)
                .add()
            .property()
                .name(ID_FIELD)
                .label("ID Field")
                .helpText("Name of the column that contains UUID identifiers")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_ID_FIELD)
                .add()
            .property()
                .name(EMAIL_FIELD)
                .label("Email Field")
                .helpText("Name of the column that contains email addresses (used as username)")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_EMAIL_FIELD)
                .add()
            .property()
                .name(PASSWORD_FIELD)
                .label("Password Field")
                .helpText("Name of the column that contains passwords")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_PASSWORD_FIELD)
                .add()
            .property()
                .name(FIRSTNAME_FIELD)
                .label("First Name Field")
                .helpText("Name of the column that contains first names")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_FIRSTNAME_FIELD)
                .add()
            .property()
                .name(LASTNAME_FIELD)
                .label("Last Name Field")
                .helpText("Name of the column that contains last names")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_LASTNAME_FIELD)
                .add()
            .property()
                .name(VALIDATION_QUERY)
                .label("Validation Query")
                .helpText("SQL query used to validate database connections")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_VALIDATION_QUERY)
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
        // Get the configured JDBC URL, username, and password
        String jdbcUrl = config.getConfig().getFirst(JDBC_URL);
        String username = config.getConfig().getFirst(DB_USERNAME);
        String password = config.getConfig().getFirst(DB_PASSWORD);

        // Validate that required properties are provided
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
        return new PostgreSQLUserStorageProvider(session, model, connectionManager);
    }

    @Override
    public void init(Config.Scope config) {
        // Load the PostgreSQL JDBC driver
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
        String usersTable = config.getConfig().getFirst(USERS_TABLE);
        String idField = config.getConfig().getFirst(ID_FIELD);
        String emailField = config.getConfig().getFirst(EMAIL_FIELD);
        String passwordField = config.getConfig().getFirst(PASSWORD_FIELD);
        String firstNameField = config.getConfig().getFirst(FIRSTNAME_FIELD);
        String lastNameField = config.getConfig().getFirst(LASTNAME_FIELD);
        
        // Use default values if not specified
        if (usersTable == null || usersTable.trim().isEmpty()) {
            usersTable = DEFAULT_USERS_TABLE;
        }
        
        if (idField == null || idField.trim().isEmpty()) {
            idField = DEFAULT_ID_FIELD;
        }
        
        if (emailField == null || emailField.trim().isEmpty()) {
            emailField = DEFAULT_EMAIL_FIELD;
        }
        
        if (passwordField == null || passwordField.trim().isEmpty()) {
            passwordField = DEFAULT_PASSWORD_FIELD;
        }
        
        if (firstNameField == null || firstNameField.trim().isEmpty()) {
            firstNameField = DEFAULT_FIRSTNAME_FIELD;
        }
        
        if (lastNameField == null || lastNameField.trim().isEmpty()) {
            lastNameField = DEFAULT_LASTNAME_FIELD;
        }
        
        return new PostgreSQLConnectionManager(
            jdbcUrl, 
            username, 
            password, 
            usersTable, 
            idField, 
            passwordField, 
            emailField, 
            firstNameField, 
            lastNameField
        );
    }
}