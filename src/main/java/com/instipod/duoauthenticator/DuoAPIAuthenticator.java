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

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.time.Instant;

public class DuoAPIAuthenticator implements Authenticator {
    public static final DuoAPIAuthenticator SINGLETON = new DuoAPIAuthenticator();

    private DuoAPIObject getDuoObject(AuthenticatorConfigModel authConfig) {
        DuoAPIObject apiObject = new DuoAPIObject(authConfig.getConfig().get(DuoAPIAuthenticatorFactory.DUO_API_HOSTNAME), authConfig.getConfig().get(DuoAPIAuthenticatorFactory.DUO_INTEGRATION_KEY), authConfig.getConfig().get(DuoAPIAuthenticatorFactory.DUO_SECRET_KEY), 10);
        return apiObject;
    }

    private void challengePushForm(AuthenticationFlowContext authenticationFlowContext, String error) {
        LoginFormsProvider form = authenticationFlowContext.form();
        if (error != null) {
            form = form.setError(error);
            form = form.setAttribute("autorefresh", false);
            form = form.setAttribute("problem", error);
        } else {
            form = form.setAttribute("autorefresh", true);
            form = form.setAttribute("problem", "none");
        }
        Response response = form.createForm("duo-push.ftl");
        if (error != null) {
            authenticationFlowContext.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, response);
        } else {
            authenticationFlowContext.challenge(response);
        }
    }

    private void challengePushForm(AuthenticationFlowContext authenticationFlowContext) {
        challengePushForm(authenticationFlowContext, null);
    }

    private void challengeCodeForm(AuthenticationFlowContext authenticationFlowContext, String capability, String error) {
        LoginFormsProvider form = authenticationFlowContext.form();
        form = form.setAttribute("capability", capability);
        if (error != null) {
            form = form.setError(error);
        }
        Response response = form.createForm("duo-code.ftl");
        if (error != null) {
            authenticationFlowContext.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, response);
        } else {
            authenticationFlowContext.challenge(response);
        }
    }

    private void challengeCodeForm(AuthenticationFlowContext authenticationFlowContext, String capability) {
        challengeCodeForm(authenticationFlowContext, capability, null);
    }

    private void handleCommError(AuthenticationFlowContext authenticationFlowContext, String message) {
        boolean failSafe = authenticationFlowContext.getAuthenticatorConfig().getConfig().getOrDefault(DuoAPIAuthenticatorFactory.DUO_FAIL_SAFE, "false").equalsIgnoreCase("true");
        if (failSafe) {
            authenticationFlowContext.success();
            return;
        } else {
            LoginFormsProvider provider = authenticationFlowContext.form();
            provider.setError(message);
            Response response = provider.createErrorPage(Response.Status.OK);
            authenticationFlowContext.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, response);
            return;
        }
    }

    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        AuthenticatorConfigModel config = authenticationFlowContext.getAuthenticatorConfig();
        if (config.getConfig().getOrDefault(DuoAPIAuthenticatorFactory.DUO_API_HOSTNAME, "none").equalsIgnoreCase("none")) {
            //authenticator not configured
            authenticationFlowContext.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
        if (config.getConfig().getOrDefault(DuoAPIAuthenticatorFactory.DUO_INTEGRATION_KEY, "none").equalsIgnoreCase("none")) {
            //authenticator not configured
            authenticationFlowContext.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
        if (config.getConfig().getOrDefault(DuoAPIAuthenticatorFactory.DUO_SECRET_KEY, "none").equalsIgnoreCase("none")) {
            //authenticator not configured
            authenticationFlowContext.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }

        DuoAPIObject duo = getDuoObject(authenticationFlowContext.getAuthenticatorConfig());

        DuoUser duoUser = duo.getUser(authenticationFlowContext.getUser().getUsername(), authenticationFlowContext.getConnection().getRemoteAddr());
        boolean refreshSuccess = duoUser.refresh();

        if (!refreshSuccess) {
            handleCommError(authenticationFlowContext, "Sorry, we are unable to retrieve your MFA options at this time!");
            return;
        }

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
                Response response = form.setAttribute("enrollUrl", duoUser.getEnrollURL()).createForm("duo-enroll.ftl");
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
            try {
                DuoPushCapableDevice pushDevice = (DuoPushCapableDevice) device;
                DuoDelayedTransaction transaction = pushDevice.push(authenticationFlowContext.getUser().getUsername(), authenticationFlowContext.getAuthenticationSession().getClient().getName(), authenticationFlowContext.getConnection().getRemoteAddr());
                authenticationFlowContext.getAuthenticationSession().setAuthNote("duo-method", "push");
                authenticationFlowContext.getAuthenticationSession().setAuthNote("duo-send-time", Long.toString(Instant.now().getEpochSecond()));
                authenticationFlowContext.getAuthenticationSession().setAuthNote("duo-transaction", transaction.getTransactionIdentifier());
                challengePushForm(authenticationFlowContext);
                return;
            } catch (Exception ex) {
                handleCommError(authenticationFlowContext, "Sorry, we were unable to send a push to your device!");
                return;
            }
        } else if (device != null && device instanceof DuoCodeCapableDevice) {
            try {
                DuoCodeCapableDevice codeDevice = (DuoCodeCapableDevice) device;
                codeDevice.challenge(authenticationFlowContext.getUser().getUsername(), authenticationFlowContext.getConnection().getRemoteAddr());
                authenticationFlowContext.getAuthenticationSession().setAuthNote("duo-method", "code");
                authenticationFlowContext.getAuthenticationSession().setAuthNote("duo-device", device.getDeviceIdentifier());
                authenticationFlowContext.getAuthenticationSession().setAuthNote("duo-capability", device.getCapabilityIdentifier());
                challengeCodeForm(authenticationFlowContext, device.getCapabilityIdentifier());
                return;
            } catch (Exception ex) {
                handleCommError(authenticationFlowContext, "Sorry, we were unable to send a code challenge!");
                return;
            }
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
        if (formData.containsKey("restart")) {
            authenticationFlowContext.getAuthenticationSession().clearAuthNotes();
            authenticationFlowContext.resetFlow();
            return;
        }
        if (formData.containsKey("resend")) {
            authenticationFlowContext.getAuthenticationSession().clearAuthNotes();
            authenticate(authenticationFlowContext);
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
                challengePushForm(authenticationFlowContext, "The push request has expired!  Click try again to send another.");
                return;
            }
            try {
                long sendTimeLong = Long.parseLong(sendTime);
                if (Instant.now().getEpochSecond() - sendTimeLong >= 60) {
                    //60 seconds to accept
                    throw new Exception("Push expired!");
                }
            } catch (Exception ex) {
                challengePushForm(authenticationFlowContext, "The push request has expired!  Click try again to send another.");
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
                    challengePushForm(authenticationFlowContext, "The push request was declined.");
                    return;
                } else {
                    //waiting
                    challengePushForm(authenticationFlowContext);
                    return;
                }
            } catch (DuoRequestFailedException e) {
                boolean failSafe = authenticationFlowContext.getAuthenticatorConfig().getConfig().getOrDefault(DuoAPIAuthenticatorFactory.DUO_FAIL_SAFE, "false").equalsIgnoreCase("true");
                if (failSafe) {
                    authenticationFlowContext.success();
                    return;
                } else {
                    challengePushForm(authenticationFlowContext);
                    return;
                }
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
            try {
                boolean result = device.checkResponse(authenticationFlowContext.getUser().getUsername(), authenticationFlowContext.getConnection().getRemoteAddr(), passcode);
                if (result) {
                    authenticationFlowContext.success();
                    return;
                } else {
                    challengeCodeForm(authenticationFlowContext, device.getCapabilityIdentifier(), "The provided passcode is not valid.");
                }
            } catch (Exception ex) {
                handleCommError(authenticationFlowContext, "Sorry, we are unable to check your passcodes at this time!");
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
