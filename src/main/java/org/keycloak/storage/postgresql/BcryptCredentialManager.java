package org.keycloak.storage.postgresql;

import org.keycloak.credential.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.credential.PasswordCredentialModel;
import at.favre.lib.crypto.bcrypt.BCrypt;

import java.util.List;
import java.util.stream.Stream;

/**
 * BcryptCredentialManager handles credential validation using BCrypt for external user repositories
 * This implementation is focused only on the SubjectCredentialManager responsibilities needed
 * for a read-only user federation provider.
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

        // Verify the password using bcrypt
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
    public boolean updateCredential(CredentialInput input) {
        // We don't support updating credentials through Keycloak
        return false;
    }

    @Override
    public void updateStoredCredential(CredentialModel cred) {
        // No-op for read-only federation
    }

    @Override
    public CredentialModel createStoredCredential(CredentialModel cred) {
        // We don't support creating credentials through Keycloak
        return null;
    }

    @Override
    public boolean removeStoredCredentialById(String id) {
        // We don't support removing credentials through Keycloak
        return false;
    }

    @Override
    public CredentialModel getStoredCredentialById(String id) {
        // No stored credentials in Keycloak
        return null;
    }

    @Override
    public Stream<CredentialModel> getStoredCredentialsStream() {
        // No stored credentials in Keycloak
        return Stream.empty();
    }

    @Override
    public Stream<CredentialModel> getStoredCredentialsByTypeStream(String type) {
        // No stored credentials in Keycloak
        return Stream.empty();
    }

    @Override
    public CredentialModel getStoredCredentialByNameAndType(String name, String type) {
        // No stored credentials in Keycloak
        return null;
    }

    @Override
    public boolean moveStoredCredentialTo(String id, String newPreviousCredentialId) {
        // We don't support moving credentials
        return false;
    }

    @Override
    public void updateCredentialLabel(String credentialId, String userLabel) {
        // No-op for read-only federation
    }

    @Override
    public void disableCredentialType(String credentialType) {
        // No-op for read-only federation
    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream() {
        return Stream.empty();
    }

    @Override
    public boolean isConfiguredFor(String type) {
        // Always return true for password credentials since they're handled externally
        return PasswordCredentialModel.TYPE.equals(type);
    }

    @Override
    public boolean isConfiguredLocally(String type) {
        return false;
    }

    @Override
    public Stream<String> getConfiguredUserStorageCredentialTypesStream() {
        return Stream.of(PasswordCredentialModel.TYPE);
    }

    @Override
    public CredentialModel createCredentialThroughProvider(CredentialModel model) {
        // This method has been deprecated so it shouldn't be called
        throw new UnsupportedOperationException("Unimplemented method 'createCredentialThroughProvider'");
    }
}