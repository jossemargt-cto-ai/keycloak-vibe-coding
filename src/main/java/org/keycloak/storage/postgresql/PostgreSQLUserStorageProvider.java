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
 * PostgreSQL User Storage Provider implementation
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
        // Not implemented in this simple example
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        // Not implemented for this simple example
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
        return connectionManager.validateUser(user.getUsername(), cred.getChallengeResponse());
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
        return users.stream().map(user -> createAdapter(realm, user));
    }
    
    protected UserModel createAdapter(RealmModel realm, PostgreSQLUserModel pgUser) {
        // Check if user already exists in local storage
        UserModel existing = session.userLocalStorage().getUserByUsername(realm, pgUser.getUsername());
        
        if (existing == null) {
            // Create the user in the Keycloak database if they don't exist yet
            UserModel imported = session.userLocalStorage().addUser(realm, pgUser.getUsername());
            imported.setFederationLink(model.getId());  // Set federation link
            imported.setEnabled(true);
            imported.setEmail(pgUser.getEmail());
            imported.setEmailVerified(true);
            imported.setFirstName(pgUser.getFirstName());
            imported.setLastName(pgUser.getLastName());
            
            logger.info("User imported from PostgreSQL: " + pgUser.getUsername());
            return imported;
        }
        
        return new PostgreSQLUserAdapter(session, realm, model, pgUser);
    }
}