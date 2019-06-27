# wso2-sample-claim-handler
## To return groupid in OIDC id_token,

1. Build with mvn clean install
2. Paste the jar to <IS_HOME>/repository/component/dropins directory
3. Change <IS_HOME>/repository/conf/identity/identity.xml as below

   ```xml
   <IDTokenCustomClaimsCallBackHandler>org.wso2.sample.identity.oauth2.grant.CustomClaimCallbackHandler</IDTokenCustomClaimsCallBackHandler>
   ```
4. Restart the server
