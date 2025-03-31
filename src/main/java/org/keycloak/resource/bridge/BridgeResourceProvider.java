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
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Bridge Resource Provider that exposes REST endpoints for token bridging.
 * This provider handles token requests by reformatting and forwarding them to the OIDC token endpoint.
 */
public class BridgeResourceProvider implements RealmResourceProvider {
    private static final Logger LOG = Logger.getLogger(BridgeResourceProvider.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

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

        // Get client from configuration
        String effectiveClientId = clientId != null ? clientId : "admin-cli";
        LOG.debugf("Using client ID: %s for realm: %s", effectiveClientId, realm.getName());

        try {
            // Parse JSON body
            Credentials credentials = MAPPER.readValue(jsonBody, Credentials.class);
            if (credentials.getUsername() == null || credentials.getPassword() == null) {
                LOG.warn("Missing username or password in request");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("{\"error\":\"invalid_request\",\"error_description\":\"Missing credentials\"}")
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .build();
            }

            // Verify client exists
            ClientModel client = realm.getClientByClientId(effectiveClientId);
            if (client == null) {
                LOG.warnf("Client %s not found in realm %s", effectiveClientId, realm.getName());
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("{\"error\":\"invalid_realm\",\"error_description\":\"Not supported\"}")
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .build();
            }

            if (!client.isEnabled()) {
                LOG.warnf("Client %s is disabled in realm %s", effectiveClientId, realm.getName());
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("{\"error\":\"invalid_client\",\"error_description\":\"Client disabled\"}")
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .build();
            }

            // Check if direct grants are allowed for client
            if (!client.isDirectAccessGrantsEnabled()) {
                LOG.warnf("Client %s does not have direct grants enabled", effectiveClientId);
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("{\"error\":\"invalid_client\",\"error_description\":\"Client not enabled for direct grants\"}")
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .build();
            }

            // Build the token endpoint URL for the realm
            String tokenEndpointUrl = buildTokenEndpointUrl(uriInfo, realm);
            LOG.debugf("Using token endpoint URL: %s", tokenEndpointUrl);

            // Prepare form parameters for OIDC token request
            Map<String, String> formParams = new HashMap<>();
            formParams.put(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD);
            formParams.put(OAuth2Constants.CLIENT_ID, effectiveClientId);
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
     * Forward the token request to the OIDC token endpoint and return the response
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

            // Build JAX-RS response
            return Response.status(statusCode)
                    .entity(responseBody)
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }
    }
}
