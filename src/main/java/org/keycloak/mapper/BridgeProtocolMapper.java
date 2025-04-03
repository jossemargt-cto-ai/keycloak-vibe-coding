package org.keycloak.mapper;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

// TODO: how this provider should be registered? (in terms of names)

/**
 * Protocol mapper that exposes all user attributes from PostgreSQL users.
 * Removes any federation prefix from attributes if present.
 */
public class BridgeProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "bridge-protocol-mapper";

    // Federation attribute prefix used by PostgreSQLUserAdapter
    private static final String FEDERATION_ATTRIBUTE_PREFIX = "FED_";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    @Override
    public String getDisplayCategory() {
        return "User bridge mapper";
    }

    @Override
    public String getDisplayType() {
        return "Bridge User Attributes";
    }

    @Override
    public String getHelpText() {
        return "Maps PostgreSQL user attributes to the ID token and UserInfo response, removing any federation prefix if present.";
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
        // TODO: We might benefit from adding some configuration properties here like explained on
        // https://www.youtube.com/watch?v=5WBb176YqKg
        // https://github.com/dasniko/keycloak-extensions-demo/blob/main/tokenmapper/src/main/java/dasniko/keycloak/tokenmapper/LuckyNumberMapper.java
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
                           KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        UserModel user = userSession.getUser();

        Map<String, List<String>> attributes = user.getAttributes();
        if (attributes == null || attributes.isEmpty()) {
            return;
        }

        // TODO: Use flag attribute instead of checking for federation link
        // This has to be reflected on the user storage provider

        for (Map.Entry<String, List<String>> entry : attributes.entrySet()) {
            String key = entry.getKey();
            List<String> values = entry.getValue();

            if (values != null && !values.isEmpty()) {
                // Convert the attribute name to a claim-friendly format
                String claimName = formatClaimName(key);

                // For single values, add as string; for multiple values, add as list
                Object claimValue = values.size() == 1 ? values.get(0) : values;
                token.getOtherClaims().put(claimName, claimValue);
            }
        }
    }

    /**
     * Format the attribute name to a claim-friendly format.
     * Removes federation prefix if present and converts to camelCase
     */
    private String formatClaimName(String attributeName) {
        if (attributeName == null || attributeName.isEmpty()) {
            return attributeName;
        }

        // Remove federation prefix if present
        if (attributeName.startsWith(FEDERATION_ATTRIBUTE_PREFIX)) {
            attributeName = attributeName.substring(FEDERATION_ATTRIBUTE_PREFIX.length());
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
