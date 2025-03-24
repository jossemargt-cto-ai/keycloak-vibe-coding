package org.keycloak.storage.postgresql;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.storage.ReadOnlyException;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapter;

import java.util.List;

/**
 * Adapter that maps a PostgreSQL user to Keycloak's UserModel in read-only mode
 */
public class PostgreSQLUserAdapter extends AbstractUserAdapter {

    private final PostgreSQLUserModel pgUser;
    private final String keycloakId;

    public PostgreSQLUserAdapter(KeycloakSession session, RealmModel realm,
                               ComponentModel storageProviderModel,
                               PostgreSQLUserModel pgUser) {
        super(session, realm, storageProviderModel);
        this.pgUser = pgUser;
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
        // We won't allow credential management from Keycloak
        return new EmptyCredentialManager(session);
    }

    @Override
    public boolean isEmailVerified() {
        return true; // For this example, we assume emails are verified
    }

    /**
     * Provide access to the underlying PostgreSQL user model
     */
    public PostgreSQLUserModel getPostgreSQLUserModel() {
        return pgUser;
    }
}