package org.keycloak.storage.postgresql;

import org.keycloak.credential.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SubjectCredentialManager;

import java.util.List;
import java.util.stream.Stream;

/**
 * EmptyCredentialManager credential manager implementation for a read-only repository of
 * external users (we simply have it to comply with the Keycloak SPI factory contract)
 */
public class EmptyCredentialManager implements SubjectCredentialManager {
    
    public EmptyCredentialManager(KeycloakSession __) {
        // No-op
    }

    @Override
    public boolean isValid(List<CredentialInput> inputs) {
        // Credential validation is handled by our CredentialInputValidator implementation
        return false;
    }

    @Override
    public boolean updateCredential(CredentialInput input) {
        // We don't support updating credentials through Keycloak
        return false;
    }

    @Override
    public void updateStoredCredential(CredentialModel cred) {
        // No-op
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
        // No-op
    }

    @Override
    public void disableCredentialType(String credentialType) {
        // No-op
    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream() {
        return Stream.empty();
    }

    @Override
    public boolean isConfiguredFor(String type) {
        // Always return true for password credentials since they're handled externally
        return CredentialModel.PASSWORD.equals(type);
    }

    @Override
    public boolean isConfiguredLocally(String type) {
        return false;
    }

    @Override
    public Stream<String> getConfiguredUserStorageCredentialTypesStream() {
        return Stream.of(CredentialModel.PASSWORD);
    }

    @Override
    public CredentialModel createCredentialThroughProvider(CredentialModel model) {
        // TODO It has been deprecated so it _shouldn't_ be called
        throw new UnsupportedOperationException("Unimplemented method 'createCredentialThroughProvider'");
    }

}