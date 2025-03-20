package org.keycloak.storage.postgresql;

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
 * with user import capability on first login
 */
public class PostgreSQLUserStorageProvider implements 
        UserStorageProvider, 
        UserLookupProvider,
        UserQueryProvider,
        CredentialInputValidator {

    private static final Logger logger = LoggerFactory.getLogger(PostgreSQLUserStorageProvider.class);
    
    protected KeycloakSession session;
    protected ComponentModel model;
    protected PostgreSQLConnectionManager connectionManager;
    
    public PostgreSQLUserStorageProvider(KeycloakSession session, ComponentModel model, PostgreSQLConnectionManager connectionManager) {
        this.session = session;
        this.model = model;
        this.connectionManager = connectionManager;
    }

    // UserStorageProvider methods
    @Override
    public void close() {
        // No resources to clean up
    }
    
    // UserLookupProvider methods
    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        String externalId = StorageId.externalId(id);
        return getUserByUsername(realm, externalId);
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        PostgreSQLUserModel pgUser = connectionManager.getUserByUsername(username);
        if (pgUser != null) {
            return createAdapter(realm, pgUser);
        }
        return null;
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        PostgreSQLUserModel pgUser = connectionManager.getUserByEmail(email);
        if (pgUser != null) {
            return createAdapter(realm, pgUser);
        }
        return null;
    }
    
    // UserQueryProvider methods
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
            List<PostgreSQLUserModel> users = connectionManager.searchForUserByUserAttribute("username", usernameSearch, maxResults != null ? maxResults : 100);
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

        // Default search across multiple fields
        List<PostgreSQLUserModel> usersByUsername = connectionManager.searchForUserByUserAttribute("username", search, maxResults != null ? maxResults : 100);
        List<PostgreSQLUserModel> usersByEmail = connectionManager.searchForUserByUserAttribute("email", search, maxResults != null ? maxResults : 100);
        
        Set<String> usernames = new HashSet<>();
        List<PostgreSQLUserModel> dedupUsers = new ArrayList<>();
        
        // Deduplicate users from different search results
        for (PostgreSQLUserModel user : usersByUsername) {
            if (!usernames.contains(user.getUsername())) {
                usernames.add(user.getUsername());
                dedupUsers.add(user);
            }
        }
        
        for (PostgreSQLUserModel user : usersByEmail) {
            if (!usernames.contains(user.getUsername())) {
                usernames.add(user.getUsername());
                dedupUsers.add(user);
            }
        }
        
        return mapToUserModelStream(realm, dedupUsers);
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult, Integer maxResults) {
        // Not implemented for read-only federation
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        // Not implemented for read-only federation
        return Stream.empty();
    }
    
    // CredentialInputValidator methods
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
        if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) {
            return false;
        }
        
        UserCredentialModel cred = (UserCredentialModel) input;
        String plainPassword = cred.getChallengeResponse();
        boolean isValid = connectionManager.validateUser(user.getUsername(), plainPassword);
        
        if (isValid) {
            // If this is a federated user, store their password after successful authentication
            if (user.getFederationLink() != null && user.getFederationLink().equals(model.getId())) {
                storeUserCredentials(realm, user, plainPassword);
            }
        }
        
        return isValid;
    }
    
    // Helper methods
    private Stream<UserModel> getAll(RealmModel realm, Integer firstResult, Integer maxResults) {
        List<PostgreSQLUserModel> users = connectionManager.getAllUsers(
                firstResult != null ? firstResult : 0,
                maxResults != null ? maxResults : Integer.MAX_VALUE
        );
        return mapToUserModelStream(realm, users);
    }
    
    private Stream<UserModel> mapToUserModelStream(RealmModel realm, List<PostgreSQLUserModel> users) {
        return users.stream().map(user -> {
            // Check if we need to import this user first
            UserModel localUser = session.users().getUserByUsername(realm, user.getUsername());
            if (localUser == null) {
                // This user doesn't exist locally yet, so we need to import
                localUser = importUser(realm, user);
            }
            return new PostgreSQLUserAdapter(session, realm, model, user);
        });
    }
    
    /**
     * Centralized method to handle user import logic
     */
    private UserModel importUser(RealmModel realm, PostgreSQLUserModel pgUser) {
        logger.info("Importing user from PostgreSQL: " + pgUser.getUsername());
        UserModel imported = session.users().addUser(realm, pgUser.getUsername());
        imported.setFederationLink(model.getId());
        imported.setEnabled(true);
        imported.setEmail(pgUser.getEmail());
        imported.setEmailVerified(true);
        imported.setFirstName(pgUser.getFirstName());
        imported.setLastName(pgUser.getLastName());
        
        // TODO: Add attributes
        
        return imported;
    }
    
    /**
     * Centralized method to handle credential storage
     */
    private void storeUserCredentials(RealmModel realm, UserModel user, String plainTextPassword) {
        if (plainTextPassword != null && !plainTextPassword.isEmpty()) {
            // Create the credential input directly as a UserCredentialModel
            UserCredentialModel credentialInput = UserCredentialModel.password(plainTextPassword);
            user.credentialManager().updateCredential(credentialInput);
            logger.debug("Stored/updated password for user: " + user.getUsername());
        }
    }
    
    protected UserModel createAdapter(RealmModel realm, PostgreSQLUserModel pgUser) {
        // Check if user already exists in local storage
        UserModel existing = session.users().getUserByUsername(realm, pgUser.getUsername());
        
        if (existing == null) {
            // Create the user in the Keycloak database if they don't exist yet
            existing = importUser(realm, pgUser);
        }
        
        return new PostgreSQLUserAdapter(session, realm, model, pgUser);
    }
}