package com.instipod.duoauthenticator;

import com.instipod.duoapi.*;
import com.instipod.duoapi.exceptions.DuoRequestFailedException;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.time.Instant;

public class DuoAPIAuthenticator implements Authenticator {
    public static final DuoAPIAuthenticator SINGLETON = new DuoAPIAuthenticator();

    private DuoAPIObject getDuoObject(AuthenticatorConfigModel authConfig) {
        DuoAPIObject apiObject = new DuoAPIObject(authConfig.getConfig().get(DuoAPIAuthenticatorFactory.DUO_API_HOSTNAME), authConfig.getConfig().get(DuoAPIAuthenticatorFactory.DUO_INTEGRATION_KEY), authConfig.getConfig().get(DuoAPIAuthenticatorFactory.DUO_SECRET_KEY), 10);
        return apiObject;
    }

    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        DuoAPIObject duo = getDuoObject(authenticationFlowContext.getAuthenticatorConfig());

        DuoUser duoUser = duo.getUser(authenticationFlowContext.getUser().getUsername(), authenticationFlowContext.getConnection().getRemoteAddr());
        duoUser.refresh();

        String defaultAction = duoUser.getDefaultAction();
        if (defaultAction.equalsIgnoreCase("allow")) {
            //allow without MFA
            authenticationFlowContext.success();
            return;
        } else if (defaultAction.equalsIgnoreCase("deny")) {
            //deny without MFA
            authenticationFlowContext.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        } else if (defaultAction.equalsIgnoreCase("enroll")) {
            //enroll the user
            if (duoUser.canEnrollHere()) {
                LoginFormsProvider form = authenticationFlowContext.form();
                MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<String, String>();
                formData.add("duo-enroll", duoUser.getEnrollURL());
                Response response = form.setFormData(formData).createForm("duo-enroll.ftl");
                authenticationFlowContext.challenge(response);
                return;
            } else {
                authenticationFlowContext.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
                return;
            }
        }

        String[] preference = new String[5];
        preference[0] = "push";
        preference[1] = "token";
        preference[2] = "mobile_otp";
        preference[3] = "phone";
        preference[4] = "sms";
        DuoDevice device = duoUser.getFirstDevice(preference);
        if (device != null && device instanceof DuoPushCapableDevice) {
            DuoPushCapableDevice pushDevice = (DuoPushCapableDevice)device;
            DuoDelayedTransaction transaction = pushDevice.push(authenticationFlowContext.getUser().getUsername(), authenticationFlowContext.getAuthenticationSession().getClient().getName(), authenticationFlowContext.getConnection().getRemoteAddr());
            authenticationFlowContext.getAuthenticationSession().setAuthNote("duo-method", "push");
            authenticationFlowContext.getAuthenticationSession().setAuthNote("duo-send-time", Long.toString(Instant.now().getEpochSecond()));
            authenticationFlowContext.getAuthenticationSession().setAuthNote("duo-transaction", transaction.getTransactionIdentifier());
            LoginFormsProvider form = authenticationFlowContext.form();
            Response response = form.createForm("duo-push.ftl");
            authenticationFlowContext.challenge(response);
            return;
        } else if (device != null && device instanceof DuoCodeCapableDevice) {
            DuoCodeCapableDevice codeDevice = (DuoCodeCapableDevice)device;
            codeDevice.challenge(authenticationFlowContext.getUser().getUsername(), authenticationFlowContext.getConnection().getRemoteAddr());
            authenticationFlowContext.getAuthenticationSession().setAuthNote("duo-method", "code");
            authenticationFlowContext.getAuthenticationSession().setAuthNote("duo-device", device.getDeviceIdentifier());
            authenticationFlowContext.getAuthenticationSession().setAuthNote("duo-capability", device.getCapabilityIdentifier());
            LoginFormsProvider form = authenticationFlowContext.form();
            MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<String, String>();
            formData.add("duo-capability", device.getCapabilityIdentifier());
            Response response = form.setFormData(formData).createForm("duo-code.ftl");
            authenticationFlowContext.challenge(response);
            return;
        } else {
            //unsupported device type or no device
            authenticationFlowContext.attempted();
            return;
        }
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {
        MultivaluedMap<String, String> formData = authenticationFlowContext.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            authenticationFlowContext.cancelLogin();
            return;
        }

        String duoMethod = authenticationFlowContext.getAuthenticationSession().getAuthNote("duo-method");
        if (duoMethod == null || duoMethod.equalsIgnoreCase("")) {
            //need to challenge again, method is empty
            authenticate(authenticationFlowContext);
            return;
        }

        if (duoMethod.equalsIgnoreCase("push")) {
            String transaction = authenticationFlowContext.getAuthenticationSession().getAuthNote("duo-transaction");
            if (transaction == null || transaction.equalsIgnoreCase("")) {
                authenticationFlowContext.failure(AuthenticationFlowError.INTERNAL_ERROR);
                return;
            }

            String sendTime = authenticationFlowContext.getAuthenticationSession().getAuthNote("duo-send-time");
            if (sendTime == null || sendTime.equalsIgnoreCase("")) {
                //force expired
                authenticationFlowContext.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
                return;
            }
            long sendTimeLong = Long.getLong(sendTime);
            if (Instant.now().getEpochSecond() - sendTimeLong > 20) {
                //20 seconds to accept
                authenticationFlowContext.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
                return;
            }

            DuoAPIObject duo = getDuoObject(authenticationFlowContext.getAuthenticatorConfig());
            DuoDelayedTransaction transactionObject = new DuoDelayedTransaction(duo, transaction);
            try {
                String result = transactionObject.checkStatus();
                if (result.equalsIgnoreCase("allow")) {
                    authenticationFlowContext.success();
                    return;
                } else if (result.equalsIgnoreCase("deny")) {
                    authenticationFlowContext.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
                    return;
                } else {
                    //waiting
                    LoginFormsProvider form = authenticationFlowContext.form();
                    Response response = form.createForm("duo-push.ftl");
                    authenticationFlowContext.challenge(response);
                    return;
                }
            } catch (DuoRequestFailedException e) {
                LoginFormsProvider form = authenticationFlowContext.form();
                Response response = form.createForm("duo-push.ftl");
                authenticationFlowContext.challenge(response);
                return;
            }
        } else if (duoMethod.equalsIgnoreCase("code")) {
            String passcode = formData.getFirst("passcode");
            String duoDevice = authenticationFlowContext.getAuthenticationSession().getAuthNote("duo-device");
            String duoCap = authenticationFlowContext.getAuthenticationSession().getAuthNote("duo-capability");
            if (duoDevice == null || duoDevice.equalsIgnoreCase("") || duoCap == null || duoCap.equalsIgnoreCase("")) {
                //need to challenge again, method is empty
                authenticate(authenticationFlowContext);
                return;
            }

            //we have a passcode and data at this point
            DuoAPIObject duo = getDuoObject(authenticationFlowContext.getAuthenticatorConfig());
            DuoCodeCapableDevice device = new DuoCodeCapableDevice(duo, duoDevice, duoCap, duoDevice);
            boolean result = device.checkResponse(authenticationFlowContext.getUser().getUsername(), authenticationFlowContext.getConnection().getRemoteAddr(), passcode);
            if (result) {
                authenticationFlowContext.success();
                return;
            } else {
                LoginFormsProvider form = authenticationFlowContext.form();
                MultivaluedHashMap<String, String> newFormData = new MultivaluedHashMap<String, String>();
                formData.add("duo-capability", duoCap);
                Response response = form.setFormData(formData).createForm("duo-code.ftl");
                authenticationFlowContext.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, response);
                return;
            }
        } else {
            //unknown method attempted
            authenticationFlowContext.attempted();
            return;
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        //not used
    }

    @Override
    public void close() {
        //not used
    }
}
