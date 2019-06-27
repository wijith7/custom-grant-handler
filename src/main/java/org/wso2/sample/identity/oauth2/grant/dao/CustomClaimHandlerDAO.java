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

package org.wso2.sample.identity.oauth2.grant.dao;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * DAO class for the custom claim handler.
 */
public class CustomClaimHandlerDAO {

    private static CustomClaimHandlerDAO instance = new CustomClaimHandlerDAO();
    private static final String SELECT_GROUP = "SELECT ROLE_NAME, ATTR_VALUE FROM IDN_SCIM_GROUP WHERE TENANT_ID = ? AND ATTR_NAME = 'urn:scim:schemas:core:1.0:id' OR ATTR_NAME = 'urn:ietf:params:scim:schemas:core:2.0:id' AND ROLE_NAME IN (";

    public CustomClaimHandlerDAO() {

    }

    public static CustomClaimHandlerDAO getInstance() {

        return instance;
    }

    public Map<String, String> getGroupIds(List<String> groupNames, int tenantId) throws IdentitySCIMException {

        Map<String, String> groupNameIdMap = new HashMap<>();
        String searchQuery = SELECT_GROUP + "'" + StringUtils.join(groupNames, "','") + "'" + ")";

        try (Connection connection = IdentityDatabaseUtil.getDBConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(searchQuery)) {

            preparedStatement.setInt(1, tenantId);

            try (ResultSet resultSet = preparedStatement.executeQuery()) {

                while (resultSet.next()) {
                    groupNameIdMap.put(resultSet.getString("ROLE_NAME"),
                            resultSet.getString("ATTR_VALUE"));
                }
            }
        } catch (SQLException e) {
            throw new IdentitySCIMException("Error when reading groupid from the persistence store.", e);
        }
        return groupNameIdMap;
    }

}
