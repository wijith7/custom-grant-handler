/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.sample.identity.oauth2.grant;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.openidconnect.DefaultOIDCClaimsCallbackHandler;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.sample.identity.oauth2.grant.dao.CustomClaimHandlerDAO;
import org.wso2.sample.identity.oauth2.grant.internal.CustomClaimHandlerDataHolder;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.core.util.IdentityTenantUtil.getTenantId;

/**
 * Custom password grant handler to return groupid in oidc id_token.
 */
public class CustomClaimCallbackHandler extends DefaultOIDCClaimsCallbackHandler {

    private static Log log = LogFactory.getLog(CustomClaimCallbackHandler.class);

    private final static String OAUTH2 = "oauth2";
    private final static String OIDC_DIALECT = "http://wso2.org/oidc/claim";
    private final static String ATTRIBUTE_SEPARATOR = FrameworkUtils.getMultiAttributeSeparator();

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder, OAuthTokenReqMessageContext
            tokenReqMessageContext) {

        JWTClaimsSet jwtClaimsSet = super.handleCustomClaims(jwtClaimsSetBuilder, tokenReqMessageContext);

        List<String> rolesList = (List<String>) jwtClaimsSet.getClaims().get("groups");
        List<String> refinedRolesList = getRefinedRolesList(tokenReqMessageContext, rolesList);
        String attributeSeparator = ",";

        String spTenantDomain = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain();
        String clientId = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getClientId();

        ServiceProvider serviceProvider = null;
        try {
            serviceProvider = getServiceProvider(spTenantDomain, clientId);
        } catch (IdentityApplicationManagementException e) {
            log.error("Error while retrieving serviceProvider for requestedClaimMappings in " + clientId, e);
        }

        ClaimMapping[] requestedClaimMappings = getRequestedClaimMappings(serviceProvider);

        boolean hasClaim = false;

        for (ClaimMapping claim : requestedClaimMappings) {
            if ("http://wso2.org/claims/groupid".equals(claim.getLocalClaim().getClaimUri())) {
                hasClaim = true;
                break;
            }
        }

        if (!hasClaim) {
            return jwtClaimsSet;
        }

        if (jwtClaimsSet == null) {
            return jwtClaimsSet;
        }

        if (jwtClaimsSet.getClaims().get("groups") == null) {
            return jwtClaimsSet;
        }

        String userTenantDomain = tokenReqMessageContext.getAuthorizedUser().getTenantDomain();
        tokenReqMessageContext.getTenantID();

        boolean isSCIMEnabled;

        isSCIMEnabled = isSCIMEnabled(tokenReqMessageContext.getAuthorizedUser().getUserStoreDomain(),
                userTenantDomain);

        if (!isSCIMEnabled) {
            return jwtClaimsSet;
        }

        JWTClaimsSet.Builder newBuilder = new JWTClaimsSet.Builder(jwtClaimsSet);

        try {
            jwtClaimsSetBuilder.claim("group_id", getGroupId(tokenReqMessageContext, refinedRolesList,
                    attributeSeparator));
        } catch (FrameworkException e) {
            log.error("Error while injecting values for group_id ", e);
        }

        jwtClaimsSet = jwtClaimsSetBuilder.build();

        return jwtClaimsSet;
    }

    private String getGroupId(OAuthTokenReqMessageContext tokenReqMessageContext, List<String> refinedRolesList,
                              String attributeSeparator) throws FrameworkException {

        try {
            Map<String, String> groupNameIdMap = CustomClaimHandlerDAO.getInstance()
                    .getGroupIds(refinedRolesList,
                            getTenantId(tokenReqMessageContext.getAuthorizedUser().getTenantDomain()));
            if (groupNameIdMap.isEmpty()) {

            }

            List<String> groupId = new ArrayList<>();
            for (Map.Entry<String, String> entry : groupNameIdMap.entrySet()) {
                groupId.add(entry.getKey() + "=" + entry.getValue());

            }
            return StringUtils.join(groupId, attributeSeparator);

        } catch (IdentitySCIMException e) {
            throw new FrameworkException("Error in getting groupids.", e);
        }

    }

    private UserStoreManager getUserManager(String tenantDomain) throws UserStoreException {

        UserStoreManager userStoreManager = null;
        try {
            RealmService realmService = CustomClaimHandlerDataHolder.getInstance().getRealmService();
            if (realmService != null) {
                int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
                UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
                if (userRealm != null) {
                    userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
                }
            } else {
                throw new UserStoreException("Can not obtain carbon realm service.");
            }
        } catch (UserStoreException e) {
            throw new UserStoreException("Error obtaining user realm for tenant: " + tenantDomain, e);
        }
        return userStoreManager;
    }

    private boolean isSCIMEnabled(String userStoreName, String userTenantDomain) {

        try {
            UserStoreManager userStoreManager = getUserManager(userTenantDomain);

            userStoreManager = userStoreManager.getSecondaryUserStoreManager(userStoreName);
            return userStoreManager.isSCIMEnabled();
        } catch (UserStoreException e) {
            log.error("Error while evaluating isSCIMEnalbed for user store " + userStoreName, e);
        }
        return false;
    }

    private List<String> getRefinedRolesList(OAuthTokenReqMessageContext tokenReqMessageContext,
                                             List<String> rolesList) {

        List<String> refinedRolesList = new ArrayList<>();

        if ("PRIMARY".equals(tokenReqMessageContext.getAuthorizedUser().getUserStoreDomain())) {
            for (String role : rolesList) {
                if (!role.contains("/")) {
                    refinedRolesList.add("PRIMARY/" + role);
                } else {
                    refinedRolesList.add(role);
                }
            }
        } else {
            refinedRolesList = rolesList;
        }

        return refinedRolesList;
    }

    private ServiceProvider getServiceProvider(String spTenantDomain,
                                               String clientId) throws IdentityApplicationManagementException {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        String spName = applicationMgtService.getServiceProviderNameByClientId(clientId, OAUTH2, spTenantDomain);

        if (log.isDebugEnabled()) {
            log.debug("Retrieving service provider for clientId: " + clientId + " in tenantDomain: "
                    + spTenantDomain);
        }
        return applicationMgtService.getApplicationExcludingFileBasedSPs(spName, spTenantDomain);
    }

    private ClaimMapping[] getRequestedClaimMappings(ServiceProvider serviceProvider) {

        if (serviceProvider.getClaimConfig() == null) {
            return new ClaimMapping[0];
        }
        return serviceProvider.getClaimConfig().getClaimMappings();
    }

}
