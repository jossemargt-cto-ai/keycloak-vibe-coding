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

    private final PostgreSQLUserModel pgUser;
    private final String keycloakId;
    private final SubjectCredentialManager credentialManager;

    // List of fields that are directly mapped to Keycloak model
    private static final List<String> MAPPED_FIELDS = List.of(
            PostgreSQLUserModel.FIELD_EMAIL,
            PostgreSQLUserModel.FIELD_EMAIL_VERIFIED,
            PostgreSQLUserModel.FIELD_FIRST_NAME,
            PostgreSQLUserModel.FIELD_LAST_NAME,
            PostgreSQLUserModel.FIELD_DISABLED
    );

    public PostgreSQLUserAdapter(KeycloakSession session, RealmModel realm,
                               ComponentModel storageProviderModel,
                               PostgreSQLUserModel pgUser,
                               SubjectCredentialManager credentialManager) {
        super(session, realm, storageProviderModel);
        this.pgUser = pgUser;
        this.credentialManager = credentialManager;
        // Use the UUID from database as the external ID for the StorageId
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

        // Add all the attributes from the PostgreSQL user with the FED_ prefix
        // Skip the directly mapped fields
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            if (value != null && !MAPPED_FIELDS.contains(key)) {
                // TODO: do we truly need to prefix with FED_?
                // TODO: Handle multiple values
                result.put("FED_" + key.toUpperCase(), Collections.singletonList(value));
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
        if (name.startsWith("FED_")) {
            String dbFieldName = name.substring(4).toLowerCase(); // Remove the FED_ prefix and convert to lowercase
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
