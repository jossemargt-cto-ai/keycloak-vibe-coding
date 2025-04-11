package com.keycloak.storage.postgresql;

import java.util.HashMap;
import java.util.Map;

/**
 * Model class representing a user entity from PostgreSQL database
 */
public class PostgreSQLUserModel {

    // Constants for standard fields that map directly to Keycloak
    public static final String FIELD_EMAIL = "email";
    public static final String FIELD_EMAIL_VERIFIED = "email_verified";
    public static final String FIELD_FIRST_NAME = "first_name";
    public static final String FIELD_LAST_NAME = "last_name";
    public static final String FIELD_DISABLED = "disabled"; // actually it is "enabled" in Keycloak

    // Constants for additional fields
    public static final String FIELD_ID = "id";
    public static final String FIELD_PASSWORD_DIGEST = "password_digest";
    public static final String FIELD_BUSINESS_NAME = "business_name";
    public static final String FIELD_BUSINESS_TYPE = "business_type";
    public static final String FIELD_BUSINESS_USER = "business_user";
    public static final String FIELD_CONFIRMATION_TOKEN = "confirmation_token";
    public static final String FIELD_CONFIRMED = "confirmed";
    public static final String FIELD_CONFIRMED_AT = "confirmed_at";
    public static final String FIELD_DELETED_AT = "deleted_at";
    public static final String FIELD_LAST_LOGIN_AT = "last_login_at";
    public static final String FIELD_LEGACY = "legacy";
    public static final String FIELD_PAYMENT_ISSUE = "payment_issue";
    public static final String FIELD_PHONE_NUMBER = "phone_number";
    public static final String FIELD_PROFILE_PIC = "profile_pic";
    public static final String FIELD_RESET_PASSWORD_CREATED_AT = "reset_password_created_at";
    public static final String FIELD_RESET_PASSWORD_TOKEN = "reset_password_token";
    public static final String FIELD_STRIPE_CUSTOMER_ID = "stripe_customer_id";
    public static final String FIELD_USER_CODE = "user_code";
    public static final String FIELD_CREATED_AT = "created_at";
    public static final String FIELD_UPDATED_AT = "updated_at";
    public static final String FIELD_ROLE = "role"; // Legacy role enum
    public static final String FIELD_SUBROLE = "subrole"; // Legacy subrole enum
    public static final String FIELD_ROLE_ID = "role_id"; // This shouldn't come but retain it as catch-all

    // Constants for role-related fields from JOIN
    public static final String FIELD_ORGANIZATION_ROLE = "organization_role";
    public static final String FIELD_ORGANIZATION_ROLE_ID = "organization_role_id";
    public static final String FIELD_ORGANIZATION_ID = "organization_id";

    // Constants for driver_user, orders and closets (not implemented yet)
    public static final String FIELD_DRIVER_USER = "driver_user";
    public static final String FIELD_ORDERS = "orders";
    public static final String FIELD_CLOSETS = "closets";

    // The map containing all user attributes
    private final Map<String, String> attributes = new HashMap<>();

    public PostgreSQLUserModel() {
        // Default constructor
    }

    public String getId() {
        return attributes.get(FIELD_ID);
    }

    public void setId(String id) {
        attributes.put(FIELD_ID, id);
    }

    public String getUsername() {
        return getEmail(); // Email is used as username
    }

    public String getEmail() {
        return attributes.get(FIELD_EMAIL);
    }

    public void setEmail(String email) {
        attributes.put(FIELD_EMAIL, email);
    }

    public String getFirstName() {
        return attributes.get(FIELD_FIRST_NAME);
    }

    public void setFirstName(String firstName) {
        attributes.put(FIELD_FIRST_NAME, firstName);
    }

    public String getLastName() {
        return attributes.get(FIELD_LAST_NAME);
    }

    public void setLastName(String lastName) {
        attributes.put(FIELD_LAST_NAME, lastName);
    }

    public boolean isEmailVerified() {
        return Boolean.parseBoolean(attributes.get(FIELD_EMAIL_VERIFIED));
    }

    public void setEmailVerified(boolean emailVerified) {
        attributes.put(FIELD_EMAIL_VERIFIED, String.valueOf(emailVerified));
    }

    public boolean isDisabled() {
        return Boolean.parseBoolean(attributes.get(FIELD_DISABLED));
    }

    public void setDisabled(boolean disabled) {
        attributes.put(FIELD_DISABLED, String.valueOf(disabled));
    }

    public String getPasswordDigest() {
        return attributes.get(FIELD_PASSWORD_DIGEST);
    }

    public void setPasswordDigest(String passwordDigest) {
        attributes.put(FIELD_PASSWORD_DIGEST, passwordDigest);
    }

    /**
     * Set an attribute value in the model
     *
     * @param name attribute name
     * @param value attribute value
     */
    public void setAttribute(String name, String value) {
        attributes.put(name, value);
    }

    /**
     * Get an attribute value from the model
     *
     * @param name attribute name
     * @return attribute value or null if not present
     */
    public String getAttribute(String name) {
        return attributes.get(name);
    }

    /**
     * Returns all attributes stored in this model
     *
     * @return Map of all attributes
     */
    public Map<String, String> getAttributes() {
        return new HashMap<>(attributes);
    }
}
