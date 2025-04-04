package org.keycloak.storage.postgresql;

import org.keycloak.credential.*;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.credential.PasswordCredentialModel;
import at.favre.lib.crypto.bcrypt.BCrypt;

import java.util.List;
import java.util.stream.Stream;

/**
 * BcryptCredentialManager handles credential validation using BCrypt for external user repositories
 * This implementation is focused only on the SubjectCredentialManager responsibilities needed
 * for a <b>read-only</b> user federation provider.
 */
public class BcryptCredentialManager implements SubjectCredentialManager {

    private final PostgreSQLConnectionManager connectionManager;
    private final String email;

    public BcryptCredentialManager(String email, PostgreSQLConnectionManager connectionManager) {
        this.email = email;
        this.connectionManager = connectionManager;
    }

    /**
     * Static method to validate a password against a stored hash using BCrypt
     * This allows other components to use the same validation logic
     */
    public static boolean validatePassword(String plainPassword, String storedPasswordHash) {
        if (storedPasswordHash == null || storedPasswordHash.isEmpty() || plainPassword == null) {
            return false;
        }

        BCrypt.Result result = BCrypt.verifyer().verify(
            plainPassword.toCharArray(),
            storedPasswordHash
        );

        return result.verified;
    }

    /**
     * Validates credential inputs such as passwords using BCrypt
     */
    @Override
    public boolean isValid(List<CredentialInput> inputs) {
        for (CredentialInput input : inputs) {
            if (supportsCredentialType(input.getType())) {
                if (!isValid(input)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Internal method to validate a single credential input
     */
    private boolean isValid(CredentialInput input) {
        if (!supportsCredentialType(input.getType())) {
            return false;
        }

        String plainPassword = input.getChallengeResponse();
        String storedPasswordHash = connectionManager.getPasswordHash(email);

        return validatePassword(plainPassword, storedPasswordHash);
    }

    public boolean supportsCredentialType(String credentialType) {
        return PasswordCredentialModel.TYPE.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(String type) {
        return PasswordCredentialModel.TYPE.equals(type);
    }

    // Bellow this line are methods that are not used in read-only federation or deprecated but required by the interface

    @Override
    public boolean updateCredential(CredentialInput input) {
        return false;
    }

    @Override
    public void updateStoredCredential(CredentialModel cred) {
        // NO-OP
    }

    @Override
    public CredentialModel createStoredCredential(CredentialModel cred) {
        return null;
    }

    @Override
    public boolean removeStoredCredentialById(String id) {
        return false;
    }

    @Override
    public CredentialModel getStoredCredentialById(String id) {
        return null;
    }

    @Override
    public Stream<CredentialModel> getStoredCredentialsStream() {
        return Stream.empty();
    }

    @Override
    public Stream<CredentialModel> getStoredCredentialsByTypeStream(String type) {
        return Stream.empty();
    }

    @Override
    public CredentialModel getStoredCredentialByNameAndType(String name, String type) {
        return null;
    }

    @Override
    public boolean moveStoredCredentialTo(String id, String newPreviousCredentialId) {
        return false;
    }

    @Override
    public void updateCredentialLabel(String credentialId, String userLabel) {
        // NO-OP
    }

    @Override
    public void disableCredentialType(String credentialType) {
        // NO-OP
    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream() {
        return Stream.empty();
    }

    @Override // Deprecated on SubjectCredentialManager
    public boolean isConfiguredLocally(String type) {
        return false;
    }

    @Override // Deprecated on SubjectCredentialManager
    public Stream<String> getConfiguredUserStorageCredentialTypesStream() {
        return Stream.of(PasswordCredentialModel.TYPE);
    }

    @Override // Deprecated on SubjectCredentialManager
    public CredentialModel createCredentialThroughProvider(CredentialModel model) {
        throw new UnsupportedOperationException("Unimplemented method 'createCredentialThroughProvider'");
    }
}
