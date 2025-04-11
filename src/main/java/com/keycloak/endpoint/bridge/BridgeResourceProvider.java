package com.keycloak.endpoint.bridge;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.core.HttpHeaders;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.IDToken;
import org.keycloak.services.resource.RealmResourceProvider;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Bridge Resource Provider that exposes REST endpoints for token bridging.
 * This provider handles token requests by reformatting and forwarding them to the OIDC token endpoint.
 */
public class BridgeResourceProvider implements RealmResourceProvider {
    private static final Logger LOG = Logger.getLogger(BridgeResourceProvider.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String USERINFO_REQ_SCOPES = "openid email profile";

    private final KeycloakSession session;
    private final String clientId;

    public BridgeResourceProvider(KeycloakSession session, String clientId) {
        this.session = session;
        this.clientId = clientId;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
        // No resources to clean up
    }

    /**
     * DTO class for parsing the credential JSON payload
     */
    public static class Credentials {
        @JsonProperty("username")
        private String username;

        @JsonProperty("password")
        private String password;

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }
    }

    /**
     * Handles the POST /token endpoint.
     * This method receives JSON credentials and forwards them to the OIDC token endpoint
     * in the form required by the direct grant flow.
     */
    @POST
    @Path("/token")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response handleTokenRequest(String jsonBody, @Context HttpHeaders headers, @Context UriInfo uriInfo) {
        RealmModel realm = session.getContext().getRealm();

        // clientid will be null upon misconfiguration, see Factory for more context
        if (clientId == null) {
            LOG.error("Bridge endpoint is misconfigured: No valid client ID specified");
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\":\"server_error\",\"error_description\":\"initialization error\"}")
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }

        try {
            Credentials credentials = MAPPER.readValue(jsonBody, Credentials.class);
            if (credentials.getUsername() == null || credentials.getPassword() == null) {
                LOG.warn("Missing username or password in request");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("{\"error\":\"invalid_request\",\"error_description\":\"Missing credentials\"}")
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .build();
            }

            String tokenEndpointUrl = buildTokenEndpointUrl(uriInfo, realm);
            LOG.debugf("Using token endpoint URL: %s", tokenEndpointUrl);

            Map<String, String> formParams = new HashMap<>();
            formParams.put(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD);
            formParams.put(OAuth2Constants.CLIENT_ID, clientId);
            formParams.put(OAuth2Constants.SCOPE, USERINFO_REQ_SCOPES);
            formParams.put("username", credentials.getUsername());
            formParams.put("password", credentials.getPassword());

            return forwardTokenRequest(tokenEndpointUrl, formParams);

        } catch (IOException e) {
            LOG.debug("Error parsing request payload", e);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"invalid_request\",\"error_description\":\"Invalid JSON payload\"}")
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        } catch (WebApplicationException e) {
            LOG.error("Error processing token request", e);
            return e.getResponse();
        } catch (Exception e) {
            LOG.error("Unexpected error processing token request", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\":\"server_error\",\"error_description\":\"Internal server error\"}")
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }
    }

    /**
     * Build the URL for the token endpoint in the current realm
     */
    private String buildTokenEndpointUrl(UriInfo uriInfo, RealmModel realm) {
        String authServerBaseUrl = uriInfo.getBaseUri().toString();
        if (authServerBaseUrl.endsWith("/")) {
            authServerBaseUrl = authServerBaseUrl.substring(0, authServerBaseUrl.length() - 1);
        }

        return authServerBaseUrl + "/realms/" + realm.getName() + "/protocol/openid-connect/token";
    }

    /**
     * Helper method to URL encode form parameter values
     */
    private String encodeFormParameter(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            // This should never happen as UTF-8 is always supported
            LOG.error("Error encoding form parameter", e);
            return value;
        }
    }

    /**
     * Forward the token request to the OIDC token endpoint, extract user info from ID token,
     * and return combined response
     */
    private Response forwardTokenRequest(String tokenEndpointUrl, Map<String, String> formParams) throws IOException {
        LOG.debug("Forwarding token request to: " + tokenEndpointUrl);

        CloseableHttpClient httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();
        HttpPost httpPost = new HttpPost(tokenEndpointUrl);

        httpPost.setHeader("Content-Type", "application/x-www-form-urlencoded");
        StringBuilder formBody = new StringBuilder();
        for (Map.Entry<String, String> param : formParams.entrySet()) {
            if (formBody.length() > 0) {
                formBody.append("&");
            }
            formBody.append(param.getKey())
                   .append("=")
                   .append(encodeFormParameter(param.getValue()));
        }
        httpPost.setEntity(new StringEntity(formBody.toString(), ContentType.APPLICATION_FORM_URLENCODED));


        try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
            int statusCode = response.getStatusLine().getStatusCode();
            String responseBody = EntityUtils.toString(response.getEntity());

            if (statusCode != 200) {
                return Response.status(statusCode)
                        .entity(responseBody)
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .build();
            }

            JsonNode tokenResponse = MAPPER.readTree(responseBody);

            if (tokenResponse.has("id_token")) {
                String idToken = tokenResponse.get("id_token").asText();

                try {
                    ObjectNode userInfo = extractUserInfoFromIdToken(idToken);

                    return createCombinedResponse(tokenResponse, userInfo);
                } catch (Exception e) {
                    LOG.error("Error extracting user info from ID token", e);
                }
            }

            return createCombinedResponse(tokenResponse, MAPPER.createObjectNode());
        }
    }

    /**
     * Extract user information from the ID token.
     *
     * NOTE: If the client is strict on the field names (ie. "sub" field comes from the ID token), or
     *       the client expects explictly "null" values instead of absent fields, this method needs to
     *       be refactored in a way it iterates over the expected fields instead of trusting the ID token.
     */
    private ObjectNode extractUserInfoFromIdToken(String idToken) {
        try {
            IDToken token = TokenVerifier.create(idToken, IDToken.class).getToken();
            ObjectNode userInfo = MAPPER.createObjectNode();

            if (token.getSubject() != null) {
                userInfo.put("sub", token.getSubject());
            }

            if (token.getPreferredUsername() != null) {
                userInfo.put("preferred_username", token.getPreferredUsername());
            }

            if (token.getName() != null) {
                userInfo.put("name", token.getName());
            }

            if (token.getGivenName() != null) {
                userInfo.put("given_name", token.getGivenName());
            }

            if (token.getFamilyName() != null) {
                userInfo.put("family_name", token.getFamilyName());
            }

            if (token.getEmail() != null) {
                userInfo.put("email", token.getEmail());
                userInfo.put("email_verified", token.getEmailVerified());
            }

            // Add other claims (Legacy ones added by the Bridge mapper)
            Map<String, Object> otherClaims = token.getOtherClaims();
            if (otherClaims == null) {
                return userInfo;
            }

            for (Map.Entry<String, Object> entry : otherClaims.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();

                if (value instanceof Integer) {
                    userInfo.put(key, (Integer) value);
                } else if (value instanceof Boolean) {
                    userInfo.put(key, (Boolean) value);
                } else if (value != null) {
                    userInfo.put(key, String.valueOf(value));
                }
            }

            return userInfo;
        } catch (Exception e) {
            LOG.error("Error parsing ID token", e);
            throw new RuntimeException("Failed to parse ID token", e);
        }
    }

    /**
     * Create a combined response with both token data and user info in a single JSON object.
     *
     * This is required to comply with the legacy clients that expect a specific format/contract.
     */
    private Response createCombinedResponse(JsonNode tokenResponse, JsonNode userInfo) throws IOException {
        ObjectNode combined = MAPPER.createObjectNode();
        ObjectNode tokenNode = MAPPER.createObjectNode();

        // Add all token fields from the original response to the token node
        tokenResponse.fieldNames().forEachRemaining(fieldName -> {
            // Skip access_token, it will be added as "token" later
            if (!fieldName.equals("access_token")) {
                tokenNode.set(fieldName, tokenResponse.get(fieldName));
            }
        });

        // Add the access_token as "token" in the token node
        if (tokenResponse.has("access_token")) {
            tokenNode.put("token", tokenResponse.get("access_token").asText());
        }

        // Add creation timestamp to the token node
        tokenNode.put("created_at", System.currentTimeMillis() / 1000); // Current time in seconds

        // Add the root members to comply with legacy contract
        combined.set("token", tokenNode);
        combined.set("user", userInfo);

        return Response.ok(MAPPER.writeValueAsString(combined), MediaType.APPLICATION_JSON_TYPE).build();
    }
}
