package com.keycloak.storage.postgresql;

import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.*;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Stream;

/**
 * PostgreSQL User Storage Provider implementation for read-only federation
 * with optional user import capability on first login
 */
public class PostgreSQLUserStorageProvider implements
        // TODO: Add GroupStorageProvider to map group membership
        UserStorageProvider,
        UserLookupProvider,
        UserQueryProvider,
        CredentialInputValidator {

    private static final Logger logger = LoggerFactory.getLogger(PostgreSQLUserStorageProvider.class);

    protected KeycloakSession session;
    protected ComponentModel model;
    protected PostgreSQLConnectionManager connectionManager;
    protected boolean importUsers;

    public PostgreSQLUserStorageProvider(KeycloakSession session, ComponentModel model,
                                        PostgreSQLConnectionManager connectionManager,
                                        boolean importUsers) {
        this.session = session;
        this.model = model;
        this.connectionManager = connectionManager;
        this.importUsers = importUsers;
    }

    @Override
    public void close() {
        // NO-OP
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        String externalId = StorageId.externalId(id);
        PostgreSQLUserModel pgUser = connectionManager.getUserById(externalId);
        if (pgUser != null) {
            return createAdapter(realm, pgUser);
        }
        return null;
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        return getUserByEmail(realm, username);
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        PostgreSQLUserModel pgUser = connectionManager.getUserByEmail(email);
        if (pgUser != null) {
            return createAdapter(realm, pgUser);
        }
        return null;
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, String search, Integer firstResult, Integer maxResults) {
        return searchForUserStream(realm, Map.of(UserModel.SEARCH, search), firstResult, maxResults);
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult, Integer maxResults) {
        String search = params.get(UserModel.SEARCH);
        if (search == null) {
            return getAll(realm, firstResult, maxResults);
        }

        String usernameSearch = params.get(UserModel.USERNAME);
        if (usernameSearch != null) {
            List<PostgreSQLUserModel> users = connectionManager.searchForUserByUserAttribute("email", usernameSearch, maxResults != null ? maxResults : 100);
            return mapToUserModelStream(realm, users);
        }

        String emailSearch = params.get(UserModel.EMAIL);
        if (emailSearch != null) {
            List<PostgreSQLUserModel> users = connectionManager.searchForUserByUserAttribute("email", emailSearch, maxResults != null ? maxResults : 100);
            return mapToUserModelStream(realm, users);
        }

        String firstName = params.get(UserModel.FIRST_NAME);
        if (firstName != null) {
            List<PostgreSQLUserModel> users = connectionManager.searchForUserByUserAttribute("firstName", firstName, maxResults != null ? maxResults : 100);
            return mapToUserModelStream(realm, users);
        }

        String lastName = params.get(UserModel.LAST_NAME);
        if (lastName != null) {
            List<PostgreSQLUserModel> users = connectionManager.searchForUserByUserAttribute("lastName", lastName, maxResults != null ? maxResults : 100);
            return mapToUserModelStream(realm, users);
        }

        List<PostgreSQLUserModel> usersByEmail = connectionManager.searchForUserByUserAttribute("email", search, maxResults != null ? maxResults : 100);
        return mapToUserModelStream(realm, usersByEmail);
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult, Integer maxResults) {
        // TODO: Implement group membership handling
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        // TODO: Not implemented yet
        return Stream.empty();
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return PasswordCredentialModel.TYPE.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType())) {
            return false;
        }

        String plainPassword = input.getChallengeResponse();
        String storedPasswordHash = connectionManager.getPasswordHash(user.getEmail());

        boolean isValid = BcryptCredentialManager.validatePassword(plainPassword, storedPasswordHash);

        // Invalid password
        if (!isValid) {
            return false;
        }

        // Import Users cap. is off
        if (!importUsers) {
            return true;
        }

        // Find local user (not federated) that matches the same email
        UserModel localUser = session.users().searchForUserByUserAttributeStream(realm, UserModel.EMAIL, user.getEmail())
            .filter(u -> u.getFederationLink() == null)
            .findFirst()
            .orElse(null);
        boolean isLocalUser = localUser != null && localUser.getId().equals(user.getId());

        // FIXME: It doesn't work as expected since the model is not a PostgreSQLUserAdapter
        // Since we might need to implement a UserFederatedStorage we'll pin this for later
        if (!isLocalUser && user instanceof PostgreSQLUserAdapter) {
            PostgreSQLUserAdapter adapter = (PostgreSQLUserAdapter) user;
            localUser = importUser(realm, adapter);
            storeUserCredentials(realm, localUser, plainPassword);
            logger.info("User imported to Keycloak database: " + user.getEmail());
        }

        return true;
    }

    private Stream<UserModel> getAll(RealmModel realm, Integer firstResult, Integer maxResults) {
        List<PostgreSQLUserModel> users = connectionManager.getAllUsers(
                firstResult != null ? firstResult : 0,
                maxResults != null ? maxResults : Integer.MAX_VALUE
        );
        return mapToUserModelStream(realm, users);
    }

    private Stream<UserModel> mapToUserModelStream(RealmModel realm, List<PostgreSQLUserModel> users) {
        return users.stream().map(user -> createAdapter(realm, user));
    }

    /**
     * Centralized method to handle user import logic
     */
    private UserModel importUser(RealmModel realm, PostgreSQLUserAdapter adapter) {
        UserModel imported = session.users().addUser(realm, adapter.getEmail());
        imported.setEnabled(adapter.isEnabled());
        imported.setEmail(adapter.getEmail());
        imported.setEmailVerified(adapter.isEmailVerified());
        imported.setFirstName(adapter.getFirstName());
        imported.setLastName(adapter.getLastName());

        // Clear all required actions that might be set by default
        imported.getRequiredActionsStream().forEach(action -> {
            imported.removeRequiredAction(action);
            logger.debug("Removed required action '" + action + "' for imported user: " + imported.getUsername());
        });

        // Import all attributes from the adapter - this will have the prefixes already applied
        adapter.getAttributes().forEach((key, values) -> {
            if (values != null && !values.isEmpty()) {
                imported.setAttribute(key, values);
            }
        });

        imported.setSingleAttribute("origin", model.getId());

        return imported;
    }

    /**
     * Centralized method to handle credential storage
     */
    private void storeUserCredentials(RealmModel realm, UserModel user, String plainTextPassword) {
        if (plainTextPassword != null && !plainTextPassword.isEmpty()) {
            UserCredentialModel credentialInput = UserCredentialModel.password(plainTextPassword);
            user.credentialManager().updateCredential(credentialInput);
            logger.debug("Stored/updated password for user: " + user.getUsername());
        }
    }

    protected UserModel createAdapter(RealmModel realm, PostgreSQLUserModel pgUser) {
        SubjectCredentialManager credentialManager = new BcryptCredentialManager(pgUser.getEmail(), connectionManager);
        return new PostgreSQLUserAdapter(session, realm, model, pgUser, credentialManager);
    }
}
