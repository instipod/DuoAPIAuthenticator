# DuoAPIAuthenticator
Authenticator for [Keycloak](https://github.com/keycloak/keycloak) that uses Duo's Auth API to present a custom interface.  This allows the Keycloak administrator to create a custom authentication theme that fits with their flow.  

The included FreeMarker templates are not designed for production use.  They are designed to be a basic example that you will extend with a custom Keycloak theme.

## Build
Make sure you have the [DuoAPIJavaClient](https://github.com/instipod/DuoAPIJavaClient) library imported into your local Maven repository.  After that, you should be able to build and package using Maven.  You will need to use the output JAR that includes dependencies as otherwise Keycloak won't be able to find the embedded libraries.

`mvn clean package`



## Using
1. First, create a new application in the Duo Admin Panel.  The application should be of the type "Auth API".
   ![Creating new application in Duo Portal!](https://github.com/instipod/DuoAPIAuthenticator/raw/master/docs/duo-admin-1.png "Step 1 in Duo Admin")
2. Add the "Duo MFA" authenticator to the a location in the Keycloak Flow that you want to protect.
   ![Creating new executor in Keycloak for Duo MFA!](https://github.com/instipod/DuoAPIAuthenticator/raw/master/docs/keycloak-1.png "Step 2 in Keycloak")
3. Set the authenticator to REQUIRED, and then click Config on the authenticator to change the settings.
   ![Config location in Keycloak admin!](https://github.com/instipod/DuoAPIAuthenticator/raw/master/docs/keycloak-2.png "Step 3 in Keycloak")
4. Copy the Integration Key, Secret Key, and API Hostname from the newly created application in the Duo Admin Panel and paste them into the boxes under Authenticator Config in Keycloak.
   ![Copying keys from Duo Portal!](https://github.com/instipod/DuoAPIAuthenticator/raw/master/docs/duo-admin-2.png "Step 4 in Duo Admin")
   ![Copying keys to Keycloak!](https://github.com/instipod/DuoAPIAuthenticator/raw/master/docs/keycloak-3.png "Step 4 in Keycloak")
5. You may now configure any policies in Duo and they will be applied in your Keycloak Flow.
