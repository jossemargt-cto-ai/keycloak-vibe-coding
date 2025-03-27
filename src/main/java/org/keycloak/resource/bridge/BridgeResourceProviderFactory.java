package org.keycloak.resource.bridge;

import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for the Bridge Resource Provider.
 * This factory creates instances of BridgeResourceProvider.
 */
public class BridgeResourceProviderFactory implements RealmResourceProviderFactory {

    private static final Logger LOG = Logger.getLogger(BridgeResourceProviderFactory.class);

    // This ID must match the resource identifier specified in the service file
    public static final String ID = "bridge";

    // Configuration property keys
    public static final String CONFIG_CLIENT_ID = "clientId";

    // Configuration fallback to environment variables
    public static final String ENV_CLIENT_ID = "BRIDGE_CLIENT_ID";

    // Default value if no configuration is provided
    public static final String DEFAULT_CLIENT_ID = "admin-cli";

    private String configuredClientId;

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        // Use configured client ID, or fall back to environment variable, or use default
        String clientId = configuredClientId;
        if (clientId == null || clientId.isEmpty()) {
            clientId = System.getenv(ENV_CLIENT_ID);

            // If still null, use default value
            if (clientId == null || clientId.isEmpty()) {
                clientId = DEFAULT_CLIENT_ID;
                LOG.debugf("Using default client ID: %s", DEFAULT_CLIENT_ID);
            }
        }

        LOG.infof("Creating Bridge Resource Provider with client ID: %s", clientId);

        return new BridgeResourceProvider(session, clientId);
    }

    @Override
    public void init(Scope config) {
        if (config != null) {
            configuredClientId = config.get(CONFIG_CLIENT_ID);
            LOG.infof("Initializing Bridge Resource Provider with configured client ID: %s",
                     configuredClientId != null ? configuredClientId : "not configured");
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization tasks needed
    }

    @Override
    public void close() {
        // No resources to clean up
    }

    @Override
    public String getId() {
        return ID;
    }
}
