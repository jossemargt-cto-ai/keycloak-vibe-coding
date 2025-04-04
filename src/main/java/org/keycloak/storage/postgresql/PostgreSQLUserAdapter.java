package org.keycloak.storage.postgresql;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.storage.ReadOnlyException;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapter;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Adapter that maps a PostgreSQL user to Keycloak's UserModel in read-only mode
 */
public class PostgreSQLUserAdapter extends AbstractUserAdapter {

    /**
     * Prefix used for all federation attributes when mapping from PostgreSQL to Keycloak
     */
    public static final String FEDERATION_ATTRIBUTE_PREFIX = "FED_";

    private final PostgreSQLUserModel pgUser;
    private final String keycloakId;
    private final SubjectCredentialManager credentialManager;

    private static final List<String> IGNORE_FIELDS = List.of(
            // Directly mapped by Keycloak
            PostgreSQLUserModel.FIELD_EMAIL,
            PostgreSQLUserModel.FIELD_EMAIL_VERIFIED,
            PostgreSQLUserModel.FIELD_FIRST_NAME,
            PostgreSQLUserModel.FIELD_LAST_NAME,
            // Indirectly mapped by Keycloak through federation
            PostgreSQLUserModel.FIELD_DISABLED,
            PostgreSQLUserModel.FIELD_PASSWORD_DIGEST,
            // Fields that we don't need to track
            PostgreSQLUserModel.FIELD_CONFIRMATION_TOKEN,
            PostgreSQLUserModel.FIELD_LAST_LOGIN_AT,
            PostgreSQLUserModel.FIELD_RESET_PASSWORD_TOKEN,
            PostgreSQLUserModel.FIELD_RESET_PASSWORD_CREATED_AT,
            PostgreSQLUserModel.FIELD_UPDATED_AT
    );

    public PostgreSQLUserAdapter(KeycloakSession session, RealmModel realm,
                               ComponentModel storageProviderModel,
                               PostgreSQLUserModel pgUser,
                               SubjectCredentialManager credentialManager) {
        super(session, realm, storageProviderModel);
        this.pgUser = pgUser;
        this.credentialManager = credentialManager;
        this.keycloakId = StorageId.keycloakId(storageProviderModel, pgUser.getId());
    }

    @Override
    public String getId() {
        return keycloakId;
    }

    @Override
    public String getUsername() {
        // Use email as username
        return pgUser.getEmail();
    }

    @Override
    public void setUsername(String username) {
        throw new ReadOnlyException("User is read-only in this federation provider");
    }

    @Override
    public String getFirstName() {
        return pgUser.getFirstName();
    }

    @Override
    public void setFirstName(String firstName) {
        throw new ReadOnlyException("User is read-only in this federation provider");
    }

    @Override
    public String getLastName() {
        return pgUser.getLastName();
    }

    @Override
    public void setLastName(String lastName) {
        throw new ReadOnlyException("User is read-only in this federation provider");
    }

    @Override
    public String getEmail() {
        return pgUser.getEmail();
    }

    @Override
    public void setEmail(String email) {
        throw new ReadOnlyException("User is read-only in this federation provider");
    }

    @Override
    public void setEmailVerified(boolean verified) {
        throw new ReadOnlyException("User is read-only in this federation provider");
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        throw new ReadOnlyException("User is read-only in this federation provider");
    }

    @Override
    public void removeAttribute(String name) {
        throw new ReadOnlyException("User is read-only in this federation provider");
    }

    @Override
    public void setSingleAttribute(String name, String value) {
        throw new ReadOnlyException("User is read-only in this federation provider");
    }

    @Override
    public SubjectCredentialManager credentialManager() {
        return credentialManager;
    }

    @Override
    public boolean isEmailVerified() {
        return pgUser.isEmailVerified();
    }

    @Override
    public boolean isEnabled() {
        return !pgUser.isDisabled();
    }

    @Override
    public void setEnabled(boolean enabled) {
        throw new ReadOnlyException("User is read-only in this federation provider");
    }

    @Override
    public Stream<String> getRequiredActionsStream() {
        // Return an empty stream to ensure no required actions are applied
        return Stream.empty();
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        Map<String, String> attributes = pgUser.getAttributes();
        Map<String, List<String>> result = super.getAttributes();

        // Add all the attributes from the PostgreSQL user with the federation prefix
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            if (value != null && !IGNORE_FIELDS.contains(key)) {
                // TODO: Handle multiple values
                result.put(FEDERATION_ATTRIBUTE_PREFIX + key.toUpperCase(), Collections.singletonList(value));
            }
        }

        return result;
    }

    @Override
    public Stream<String> getAttributeStream(String name) {
        // If it's a standard attribute mapped directly, use the super implementation
        if (super.getAttributes().containsKey(name)) {
            return super.getAttributeStream(name);
        }

        // Check if it's one of our prefixed attributes
        if (name.startsWith(FEDERATION_ATTRIBUTE_PREFIX)) {
            String dbFieldName = name.substring(FEDERATION_ATTRIBUTE_PREFIX.length()).toLowerCase(); // Remove the prefix and convert to lowercase
            String value = pgUser.getAttribute(dbFieldName);
            return value != null ? Stream.of(value) : Stream.empty();
        }

        return Stream.empty();
    }

    @Override
    public List<String> getAttribute(String name) {
        return getAttributeStream(name).toList();
    }

    /**
     * Provide access to the underlying PostgreSQL user model
     */
    public PostgreSQLUserModel getPostgreSQLUserModel() {
        return pgUser;
    }
}
