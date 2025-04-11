package com.keycloak.storage.postgresql;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.storage.ReadOnlyException;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapter;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Adapter that maps a PostgreSQL user to Keycloak's UserModel
 */
public class PostgreSQLUserAdapter extends AbstractUserAdapter {

    /**
     * Prefix used for all federation attributes when mapping from PostgreSQL to Keycloak
     */
    public static final String FEDERATION_ATTRIBUTE_PREFIX = "FED_";

    private static final Map<String, String> DEFAULT_MAPPED_ATTRIBUTES = Map.of(
        PostgreSQLUserModel.FIELD_EMAIL, UserModel.EMAIL,
        PostgreSQLUserModel.FIELD_EMAIL_VERIFIED, UserModel.EMAIL_VERIFIED,
        PostgreSQLUserModel.FIELD_FIRST_NAME, UserModel.FIRST_NAME,
        PostgreSQLUserModel.FIELD_LAST_NAME, UserModel.LAST_NAME
    );

    private static final List<String> IGNORE_ATTRIBUTES = List.of(
            // Indirectly mapped by Keycloak through federation
            PostgreSQLUserModel.FIELD_DISABLED,
            PostgreSQLUserModel.FIELD_PASSWORD_DIGEST,
            // Fields that we don't need to track
            PostgreSQLUserModel.FIELD_CONFIRMATION_TOKEN,
            PostgreSQLUserModel.FIELD_LAST_LOGIN_AT,
            PostgreSQLUserModel.FIELD_RESET_PASSWORD_TOKEN,
            PostgreSQLUserModel.FIELD_RESET_PASSWORD_CREATED_AT,
            // Role and subrole will be handled separately
            PostgreSQLUserModel.FIELD_ROLE,
            PostgreSQLUserModel.FIELD_SUBROLE,
            PostgreSQLUserModel.FIELD_ROLE_ID
    );

    private static final Map<String, String> ROLE_MAP;
    private static final Map<String, String> SUBROLE_MAP;
    private static final String DEFAULT_ROLE = "is_client";

    static {
        // Initializing role map
        Map<String, String> roleMap = new HashMap<>();
        roleMap.put("0", "is_admin");
        roleMap.put("1", "is_client");
        roleMap.put("2", "is_fullfillment_client");
        ROLE_MAP = Collections.unmodifiableMap(roleMap);

        // Initializing subrole map
        Map<String, String> subroleMap = new HashMap<>();
        subroleMap.put("0", "operation_specialist");
        subroleMap.put("1", "support");
        subroleMap.put("2", "supervisor");
        subroleMap.put("3", "operation_manager");
        subroleMap.put("4", "super");
        subroleMap.put("5", "driver");
        subroleMap.put("6", "mover");
        subroleMap.put("7", "god");
        SUBROLE_MAP = Collections.unmodifiableMap(subroleMap);
    }

    private final PostgreSQLUserModel pgUser;
    private final String keycloakId;
    private final SubjectCredentialManager credentialManager;

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

        for (Map.Entry<String, String> entry : DEFAULT_MAPPED_ATTRIBUTES.entrySet()) {
            String pgField = entry.getKey();
            String keycloakField = entry.getValue();
            String value = attributes.get(pgField);

            if (value != null) {
                result.put(keycloakField, Collections.singletonList(value));
            }
        }

        result.put(FEDERATION_ATTRIBUTE_PREFIX + PostgreSQLUserModel.FIELD_ROLE.toUpperCase(),
                Collections.singletonList(mapRole(attributes.get(PostgreSQLUserModel.FIELD_ROLE))));

        String mappedSubrole = mapSubrole(attributes.get(PostgreSQLUserModel.FIELD_SUBROLE));
        if (mappedSubrole != null) {
            result.put(FEDERATION_ATTRIBUTE_PREFIX + PostgreSQLUserModel.FIELD_SUBROLE.toUpperCase(),
                    Collections.singletonList(mappedSubrole));
        }

        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            if (value != null &&
                !DEFAULT_MAPPED_ATTRIBUTES.containsKey(key) &&
                !IGNORE_ATTRIBUTES.contains(key)) {
                result.put(FEDERATION_ATTRIBUTE_PREFIX + key.toUpperCase(),
                        Collections.singletonList(value));
            }
        }

        return result;
    }

    @Override
    public Stream<String> getAttributeStream(String name) {
        if ((FEDERATION_ATTRIBUTE_PREFIX + PostgreSQLUserModel.FIELD_ROLE.toUpperCase()).equals(name)) {
            String roleId = pgUser.getAttribute(PostgreSQLUserModel.FIELD_ROLE);
            return Stream.of(mapRole(roleId));
        }

        if ((FEDERATION_ATTRIBUTE_PREFIX + PostgreSQLUserModel.FIELD_SUBROLE.toUpperCase()).equals(name)) {
            String subroleId = pgUser.getAttribute(PostgreSQLUserModel.FIELD_SUBROLE);
            String mappedSubrole = mapSubrole(subroleId);
            return mappedSubrole != null ? Stream.of(mappedSubrole) : Stream.empty();
        }

        if (name.startsWith(FEDERATION_ATTRIBUTE_PREFIX)) {
            String dbFieldName = name.substring(FEDERATION_ATTRIBUTE_PREFIX.length()).toLowerCase();
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

    /**
     * Maps the numeric role ID to its string representation
     *
     * @param roleId the numeric role ID from the database
     * @return the string representation of the role
     */
    private String mapRole(String roleId) {
        if (roleId == null || roleId.isEmpty()) {
            return DEFAULT_ROLE;
        }
        return ROLE_MAP.getOrDefault(roleId, DEFAULT_ROLE);
    }

    /**
     * Maps the numeric subrole ID to its string representation
     *
     * @param subroleId the numeric subrole ID from the database
     * @return the string representation of the subrole, or null if not found
     */
    private String mapSubrole(String subroleId) {
        if (subroleId == null || subroleId.isEmpty()) {
            return null;
        }
        return SUBROLE_MAP.get(subroleId);
    }
}
