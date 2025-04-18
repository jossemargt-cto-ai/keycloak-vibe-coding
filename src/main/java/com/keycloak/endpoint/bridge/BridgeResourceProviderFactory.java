package com.keycloak.endpoint.bridge;

import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for the Bridge Resource Provider.
 *
 * This factory creates instances of {@link BridgeResourceProvider} which provide bridge functionality
 * between legacy authentication systems and Keycloak.
 *
 * The factory requires configuration of a client ID that will be used for processing bridge
 * authentication requests. This client must have direct grants enabled and should have the
 * bridge-legacy-auth scope assigned to it.</p
 *
 * Configuration can be provided through SPI config or environment variables:
 *   - clientId - REQUIRED - The client ID to use for bridge authentication (env: KC_SPI_BRIDGE_CLIENT_ID) (param: --spi-realm-restapi-extension-bridge-client-id)
 *   - requiredScope - OPTIONAL- The client scope that allows bridge flows (env: KC_SPI_BRIDGE_REQUIRED_SCOPE) (param: --spi-realm-restapi-extension-bridge-required-scope)
 *
 * If the provider is not properly configured or the specified client does not exist or
 * does not meet the requirements, appropriate error messages will be logged and the
 * provider will be created with a null client ID, effectively disabling its functionality.
 */
public class BridgeResourceProviderFactory implements RealmResourceProviderFactory {
    public static final String ID = "bridge";
    public static final String CONFIG_CLIENT_ID = "clientId";
    public static final String CONFIG_REQUIRED_SCOPE = "requiredScope";

    public static final String ENV_CLIENT_ID = "KC_SPI_BRIDGE_CLIENT_ID";
    public static final String ENV_REQUIRED_SCOPE = "KC_SPI_BRIDGE_REQUIRED_SCOPE";
    public static final String DEFAULT_REQUIRED_SCOPE = "bridge-legacy-auth";

    private static final Logger LOG = Logger.getLogger(BridgeResourceProviderFactory.class);

    private String configuredClientId;
    private String configuredRequiredScope;

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        final String clientId = configuredClientId != null && !configuredClientId.isEmpty()
                ? configuredClientId
                : System.getenv(ENV_CLIENT_ID);

        final String requiredScope = configuredRequiredScope != null && !configuredRequiredScope.isEmpty()
                ? configuredRequiredScope
                : System.getenv().getOrDefault(ENV_REQUIRED_SCOPE, DEFAULT_REQUIRED_SCOPE);

        if (clientId == null || clientId.isEmpty()) {
            LOG.error("Bridge endpoint is misconfigured: No client ID specified");
            return new BridgeResourceProvider(session, null);
        }

        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(clientId);

        if (client == null) {
            LOG.warnf("Bridge endpoint is misconfigured for realm %s, missing %s Client", realm.getName(), clientId);
            return new BridgeResourceProvider(session, null);
        }

        if (!client.isEnabled()) {
            LOG.errorf("Bridge endpoint is misconfigured: Client %s is disabled in realm %s", clientId,
                    realm.getName());
            return new BridgeResourceProvider(session, null);
        }

        if (!client.isDirectAccessGrantsEnabled()) {
            LOG.errorf("Bridge endpoint is misconfigured: Client %s does not have direct grants enabled", clientId);
            return new BridgeResourceProvider(session, null);
        }

        boolean hasRequiredScope = client.getClientScopes(true).get(requiredScope) != null;
        if (!hasRequiredScope) {
            LOG.warnf("Client %s does not have the '%s' scope on its default scopes", clientId,
                    requiredScope);
        }

        return new BridgeResourceProvider(session, clientId);
    }

    /**
     * Initializes the factory with configuration parameters.
     *
     * @param config The configuration scope containing the parameters (can be null).
     *
     * @see https://www.keycloak.org/server/configuration-provider for details on configuration flags.
     */
    @Override
    public void init(Scope config) {
        if (config != null) {
            configuredClientId = config.get(CONFIG_CLIENT_ID);
            configuredRequiredScope = config.get(CONFIG_REQUIRED_SCOPE);
        }
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // NO-OP
    }

    @Override
    public void close() {
        // NO-OP
    }
}
