package org.keycloak.resource.bridge;

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
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
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
    private static final String USERINFO_REQ_SCOPES = "openid";

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

        // Verify that the client ID is not null (would happen if misconfigured in factory)
        if (clientId == null) {
            LOG.error("Bridge endpoint is misconfigured: No valid client ID specified");
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\":\"server_error\",\"error_description\":\"initialization error\"}")
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }

        try {
            // Parse and process the credentials
            Credentials credentials = MAPPER.readValue(jsonBody, Credentials.class);
            if (credentials.getUsername() == null || credentials.getPassword() == null) {
                LOG.warn("Missing username or password in request");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("{\"error\":\"invalid_request\",\"error_description\":\"Missing credentials\"}")
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .build();
            }

            // Build the token endpoint URL for the realm
            String tokenEndpointUrl = buildTokenEndpointUrl(uriInfo, realm);
            LOG.debugf("Using token endpoint URL: %s", tokenEndpointUrl);

            // Prepare form parameters for OIDC token request
            Map<String, String> formParams = new HashMap<>();
            formParams.put(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD);
            formParams.put(OAuth2Constants.CLIENT_ID, clientId);
            formParams.put(OAuth2Constants.SCOPE, USERINFO_REQ_SCOPES);
            formParams.put("username", credentials.getUsername());
            formParams.put("password", credentials.getPassword());

            // Forward the request to the token endpoint and return the response
            return forwardTokenRequest(tokenEndpointUrl, formParams);

        } catch (IOException e) {
            LOG.error("Error parsing request payload", e);
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
        // Use the KeycloakSession's context to get the correct base URL that respects Keycloak's configuration
        String authServerBaseUrl = uriInfo.getBaseUri().toString();
        if (authServerBaseUrl.endsWith("/")) {
            authServerBaseUrl = authServerBaseUrl.substring(0, authServerBaseUrl.length() - 1);
        }

        return authServerBaseUrl + "/realms/" + realm.getName() + "/protocol/openid-connect/token";
    }

    /**
     * Build the URL for the userinfo endpoint in the current realm
     */
    private String buildUserInfoEndpointUrl(UriInfo uriInfo, RealmModel realm) {
        // Use the KeycloakSession's context to get the correct base URL that respects Keycloak's configuration
        String authServerBaseUrl = uriInfo.getBaseUri().toString();
        if (authServerBaseUrl.endsWith("/")) {
            authServerBaseUrl = authServerBaseUrl.substring(0, authServerBaseUrl.length() - 1);
        }

        return authServerBaseUrl + "/realms/" + realm.getName() + "/protocol/openid-connect/userinfo";
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
     * Forward the token request to the OIDC token endpoint, then get user info, and return combined response
     */
    private Response forwardTokenRequest(String tokenEndpointUrl, Map<String, String> formParams) throws IOException {
        LOG.debug("Forwarding token request to: " + tokenEndpointUrl);

        // Get the HttpClient from Keycloak's HttpClientProvider
        CloseableHttpClient httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();

        // Create POST request to token endpoint
        HttpPost httpPost = new HttpPost(tokenEndpointUrl);
        httpPost.setHeader("Content-Type", "application/x-www-form-urlencoded");

        // Build form URL encoded body
        StringBuilder formBody = new StringBuilder();
        for (Map.Entry<String, String> param : formParams.entrySet()) {
            if (formBody.length() > 0) {
                formBody.append("&");
            }
            formBody.append(param.getKey())
                   .append("=")
                   .append(encodeFormParameter(param.getValue()));
        }

        // Set request entity
        httpPost.setEntity(new StringEntity(formBody.toString(), ContentType.APPLICATION_FORM_URLENCODED));

        // Execute request
        try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
            // Get response status
            int statusCode = response.getStatusLine().getStatusCode();

            // Get response body
            String responseBody = EntityUtils.toString(response.getEntity());

            // If the token request was not successful, just return the error response
            if (statusCode != 200) {
                return Response.status(statusCode)
                        .entity(responseBody)
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .build();
            }

            // Parse the token response to get the access token
            JsonNode tokenResponse = MAPPER.readTree(responseBody);
            if (tokenResponse.has("access_token")) {
                String accessToken = tokenResponse.get("access_token").asText();

                // Fetch user info using the access token
                UriInfo uriInfo = session.getContext().getUri();
                RealmModel realm = session.getContext().getRealm();
                String userInfoUrl = buildUserInfoEndpointUrl(uriInfo, realm);

                JsonNode userInfo = fetchUserInfo(userInfoUrl, accessToken);

                // Create a combined response with both token and user metadata
                return createCombinedResponse(tokenResponse, userInfo);
            }

            // If we couldn't get the access token for some reason, return the original response
            return Response.status(statusCode)
                    .entity(responseBody)
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }
    }

    /**
     * Fetch user information from the OIDC userinfo endpoint
     */
    private JsonNode fetchUserInfo(String userInfoUrl, String accessToken) throws IOException {
        LOG.debug("Fetching user info from: " + userInfoUrl);

        // Get the HttpClient from Keycloak's HttpClientProvider
        CloseableHttpClient httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();

        // Create GET request to userinfo endpoint
        org.apache.http.client.methods.HttpGet httpGet = new org.apache.http.client.methods.HttpGet(userInfoUrl);
        httpGet.setHeader("Authorization", "Bearer " + accessToken);

        // Execute request
        try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
            // Get response status
            int statusCode = response.getStatusLine().getStatusCode();

            // Get response body
            String responseBody = EntityUtils.toString(response.getEntity());

            if (statusCode == 200) {
                return MAPPER.readTree(responseBody);
            } else {
                LOG.warnf("Failed to get user info, status: %d, response: %s", statusCode, responseBody);
                return MAPPER.createObjectNode();
            }
        }
    }

    /**
     * Create a combined response with both token data and user info in a single JSON object.
     *
     * This is required to comply with the legacy clients that expect a specific format/contract.
     */
    private Response createCombinedResponse(JsonNode tokenResponse, JsonNode userInfo) throws IOException {
        // Create our new response structure with only two root nodes: token and user
        ObjectNode combined = MAPPER.createObjectNode();

        // Create the token object that will contain all token-related fields
        ObjectNode tokenNode = MAPPER.createObjectNode();

        // Add all token fields from the original response to the token node
        tokenResponse.fieldNames().forEachRemaining(fieldName -> {
            // Skip access_token as we'll add it specifically as "token"
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

        // Add the token node to the combined response
        combined.set("token", tokenNode);

        // Add user info under the user member
        combined.set("user", userInfo);

        return Response.ok(MAPPER.writeValueAsString(combined), MediaType.APPLICATION_JSON_TYPE).build();
    }
}
