package org.keycloak.storage.postgresql;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapter;

/**
 * Adapter that maps a PostgreSQL user to Keycloak's UserModel
 */
public class PostgreSQLUserAdapter extends AbstractUserAdapter {

    private final PostgreSQLUserModel pgUser;
    private final String keycloakId;

    public PostgreSQLUserAdapter(KeycloakSession session, RealmModel realm,
                               ComponentModel storageProviderModel,
                               PostgreSQLUserModel pgUser) {
        super(session, realm, storageProviderModel);
        this.pgUser = pgUser;
        this.keycloakId = StorageId.keycloakId(storageProviderModel, pgUser.getUsername());
    }

    @Override
    public String getId() {
        return keycloakId;
    }

    @Override
    public String getUsername() {
        return pgUser.getUsername();
    }

    @Override
    public String getFirstName() {
        return pgUser.getFirstName();
    }

    @Override
    public String getLastName() {
        return pgUser.getLastName();
    }

    @Override
    public String getEmail() {
        return pgUser.getEmail();
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
}