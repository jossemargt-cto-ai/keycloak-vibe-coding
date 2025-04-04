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
 * Protocol mapper bridges the gap between legacy and OIDC ID token and UserInfo formats.
 */
public class BridgeOIDCProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "bridge-OIDC-protocol-mapper";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

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

        for (Map.Entry<String, List<String>> entry : attributes.entrySet()) {
            String key = entry.getKey();
            List<String> values = entry.getValue();

            if (values == null || values.isEmpty() || key == null || key.isEmpty()) {
                continue;
            }

            if (!key.startsWith(PostgreSQLUserAdapter.FEDERATION_ATTRIBUTE_PREFIX)) {
                continue;
            }

            String attributeName = key.substring(PostgreSQLUserAdapter.FEDERATION_ATTRIBUTE_PREFIX.length()).toLowerCase();
            if (!isFieldConstant(attributeName) || isIgnoredField(attributeName)) {
                continue;
            }

            String claimName = formatClaimName(attributeName);
            String value = values.get(0);
            token.getOtherClaims().put(claimName, value);
        }
    }

    /**
     * Checks if the given field name corresponds to a constant field in PostgreSQLUserModel
     */
    private boolean isFieldConstant(String fieldName) {
        return fieldName.equals(PostgreSQLUserModel.FIELD_ID) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_BUSINESS_NAME) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_BUSINESS_TYPE) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_BUSINESS_USER) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_CONFIRMED) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_CONFIRMED_AT) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_DELETED_AT) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_LEGACY) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_PAYMENT_ISSUE) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_PHONE_NUMBER) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_PROFILE_PIC) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_ROLE) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_SUBROLE) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_USER_CODE) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_CREATED_AT) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_ROLE_ID) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_STRIPE_CUSTOMER_ID);
    }

    /**
     * Checks if the given field name is in the IGNORE_FIELDS list of PostgreSQLUserAdapter
     */
    private boolean isIgnoredField(String fieldName) {
        return fieldName.equals(PostgreSQLUserModel.FIELD_EMAIL) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_EMAIL_VERIFIED) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_FIRST_NAME) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_LAST_NAME) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_DISABLED) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_PASSWORD_DIGEST) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_CONFIRMATION_TOKEN) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_LAST_LOGIN_AT) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_RESET_PASSWORD_TOKEN) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_RESET_PASSWORD_CREATED_AT) ||
               fieldName.equals(PostgreSQLUserModel.FIELD_UPDATED_AT);
    }

    /**
     * Format the attribute name to a claim-friendly format (from snake to camel case).
     */
    private String formatClaimName(String attributeName) {
        if (attributeName == null || attributeName.isEmpty()) {
            return attributeName;
        }

        StringBuilder result = new StringBuilder();
        boolean capitalizeNext = false;

        for (char c : attributeName.toCharArray()) {
            if (c == '_') {
                capitalizeNext = true;
            } else {
                if (capitalizeNext) {
                    result.append(Character.toUpperCase(c));
                    capitalizeNext = false;
                } else {
                    result.append(c);
                }
            }
        }

        return result.toString();
    }
}
