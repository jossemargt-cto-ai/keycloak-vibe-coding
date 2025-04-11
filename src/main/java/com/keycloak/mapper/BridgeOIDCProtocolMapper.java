package com.keycloak.mapper;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import com.keycloak.storage.postgresql.PostgreSQLUserAdapter;
import com.keycloak.storage.postgresql.PostgreSQLUserModel;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Protocol mapper bridges the gap between legacy and OIDC ID token and UserInfo
 * formats.
 *
 * NOTE: There's a high chance that this componentent will be dropped in the
 * future, if the clients are too rigid to not accept "omit when null" claims.
 * In that scenario, the legacy claims will be added at the RealmResource level
 * instead.
 */
public class BridgeOIDCProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "bridge-OIDC-protocol-mapper";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    // List of all fields to check for mapping
    private static final String[] ALL_FIELDS_TO_MAP = {
            PostgreSQLUserModel.FIELD_ID,
            PostgreSQLUserModel.FIELD_BUSINESS_NAME,
            PostgreSQLUserModel.FIELD_BUSINESS_TYPE,
            PostgreSQLUserModel.FIELD_BUSINESS_USER,
            PostgreSQLUserModel.FIELD_CONFIRMED,
            PostgreSQLUserModel.FIELD_LEGACY,
            PostgreSQLUserModel.FIELD_PAYMENT_ISSUE,
            PostgreSQLUserModel.FIELD_PHONE_NUMBER,
            PostgreSQLUserModel.FIELD_USER_CODE,
            PostgreSQLUserModel.FIELD_CREATED_AT,
            // PostgreSQLUserModel.FIELD_UPDATED_AT, // FIXME: ID Token parser trips over this value
            PostgreSQLUserModel.FIELD_STRIPE_CUSTOMER_ID,
            // Role releated claims
            PostgreSQLUserModel.FIELD_ROLE,
            PostgreSQLUserModel.FIELD_SUBROLE,
            PostgreSQLUserModel.FIELD_ORGANIZATION_ROLE,
            PostgreSQLUserModel.FIELD_ORGANIZATION_ROLE_ID,
            PostgreSQLUserModel.FIELD_ORGANIZATION_ID,
            // Dummy null claims (not implemented yet)
            PostgreSQLUserModel.FIELD_DRIVER_USER,
            PostgreSQLUserModel.FIELD_ORDERS,
            PostgreSQLUserModel.FIELD_CLOSETS
    };

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Bridge User Attributes";
    }

    @Override
    public String getHelpText() {
        return "Maps legacy user attributes";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, BridgeOIDCProtocolMapper.class);
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
            KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        UserModel user = userSession.getUser();
        Map<String, List<String>> attributes = user.getAttributes();

        if (attributes == null || attributes.isEmpty()) {
            return;
        }

        for (String fieldName : ALL_FIELDS_TO_MAP) {
            if (isIgnoredField(fieldName)) {
                continue;
            }

            String attributeKey = PostgreSQLUserAdapter.FEDERATION_ATTRIBUTE_PREFIX + fieldName.toUpperCase();
            String claimName = formatClaimName(fieldName);

            if (!attributes.containsKey(attributeKey) || attributes.get(attributeKey).isEmpty()) {
                if (isBoolean(fieldName)) {
                    token.getOtherClaims().put(claimName, false);
                } else if (isNumeric(fieldName)) {
                    token.getOtherClaims().put(claimName, 0);
                } else {
                    token.getOtherClaims().put(claimName, null);
                }
                continue;
            }

            String value = attributes.get(attributeKey).get(0);
            if (isBoolean(fieldName)) {
                token.getOtherClaims().put(claimName, Boolean.parseBoolean(value));
            } else if (isNumeric(fieldName)) {
                try {
                    token.getOtherClaims().put(claimName, Integer.parseInt(value));
                } catch (NumberFormatException e) {
                    token.getOtherClaims().put(claimName, 0);
                }
            } else {
                token.getOtherClaims().put(claimName, value);
            }
        }
    }

    /**
     * Determines if a field should be treated as a boolean value
     */
    private boolean isBoolean(String fieldName) {
        return fieldName.equals(PostgreSQLUserModel.FIELD_CONFIRMED) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_LEGACY) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_PAYMENT_ISSUE) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_BUSINESS_USER);
    }

    /**
     * Determines if a field should be treated as a numeric value
     */
    private boolean isNumeric(String fieldName) {
        return fieldName.equals(PostgreSQLUserModel.FIELD_ORDERS) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_CLOSETS);
    }

    /**
     * Checks if the given field name is in the IGNORE_FIELDS list of
     * PostgreSQLUserAdapter
     */
    private boolean isIgnoredField(String fieldName) {
        return fieldName.equals(PostgreSQLUserModel.FIELD_EMAIL) || // Standard claim
                fieldName.equals(PostgreSQLUserModel.FIELD_EMAIL_VERIFIED) || // Standard claim
                fieldName.equals(PostgreSQLUserModel.FIELD_FIRST_NAME) || // Standard claim
                fieldName.equals(PostgreSQLUserModel.FIELD_LAST_NAME) || // Standard claim
                fieldName.equals(PostgreSQLUserModel.FIELD_DISABLED) ||
                fieldName.equals(PostgreSQLUserModel.FIELD_PASSWORD_DIGEST) ||
                fieldName.equals(PostgreSQLUserModel.FIELD_CONFIRMATION_TOKEN) ||
                fieldName.equals(PostgreSQLUserModel.FIELD_LAST_LOGIN_AT) ||
                fieldName.equals(PostgreSQLUserModel.FIELD_RESET_PASSWORD_TOKEN) ||
                fieldName.equals(PostgreSQLUserModel.FIELD_RESET_PASSWORD_CREATED_AT) ||
                fieldName.equals(PostgreSQLUserModel.FIELD_DELETED_AT) ||
                fieldName.equals(PostgreSQLUserModel.FIELD_PROFILE_PIC) ||
                fieldName.equals(PostgreSQLUserModel.FIELD_CONFIRMED_AT);
    }

    /**
     * Format the attribute name to the format expected by the client (lower snake
     * cases).
     */
    private String formatClaimName(String attributeName) {
        if (attributeName == null || attributeName.isEmpty()) {
            return attributeName;
        }

        return attributeName.toLowerCase().replaceAll("-", "_");
    }
}
