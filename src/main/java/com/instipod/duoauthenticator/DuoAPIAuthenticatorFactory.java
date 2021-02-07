package com.instipod.duoauthenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.Collections;
import java.util.List;

public class DuoAPIAuthenticatorFactory implements AuthenticatorFactory {
    public static final String PROVIDER_ID = "duo-api";
    private static List<ProviderConfigProperty> commonConfig;

    protected static final String DUO_API_HOSTNAME = "duoApiHostname";
    protected static final String DUO_INTEGRATION_KEY = "duoIntegrationKey";
    protected static final String DUO_SECRET_KEY = "duoSecretKey";

    static {
        commonConfig = Collections.unmodifiableList(ProviderConfigurationBuilder.create()
                .property().name(DUO_API_HOSTNAME).label("Duo API Hostname").helpText("Domain name to contact").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name(DUO_INTEGRATION_KEY).label("Duo Integration Key").helpText("Obtained from admin console").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name(DUO_SECRET_KEY).label("Duo Secret Key").helpText("Obtained from admin console").type(ProviderConfigProperty.STRING_TYPE).add()
                .build()
        );
    }

    @Override
    public String getDisplayType() {
        return "Duo MFA";
    }

    @Override
    public String getReferenceCategory() {
        return "MFA";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Allows you to use Duo as a second authenticator.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return commonConfig;
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return DuoAPIAuthenticator.SINGLETON;
    }

    @Override
    public void init(Config.Scope scope) {
        //noop
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
        //noop
    }

    @Override
    public void close() {
        //noop
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
