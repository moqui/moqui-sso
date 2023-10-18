package org.moqui.sso

import org.moqui.context.ExecutionContext
import org.moqui.entity.EntityList
import org.moqui.entity.EntityValue
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.engine.SecurityGrantedAccessAdapter
import org.pac4j.core.profile.UserProfile

import java.sql.Timestamp

/**
 * Handles creation of Moqui user accounts.
 */
class MoquiSecurityGrantedAccessAdapter implements SecurityGrantedAccessAdapter {

    /**
     * Execution context used to access facades.
     */
    private ExecutionContext ec

    /**
     * Initializes a new {@code MoquiSecurityGrantedAccessAdapter}.
     */
    MoquiSecurityGrantedAccessAdapter(ExecutionContext ec) {
        this.ec = ec
    }

    private Map<String, Object> mapProfileFields(EntityList fieldMaps, Map attributeMap) {
        Map<String, Object> destinationMap = new HashMap<>()

        fieldMaps.forEach {
            Object srcFieldValue = ec.resource.expression(it.dstFieldExpression as String ?: it.srcFieldName as String, null, attributeMap)
            if (srcFieldValue) {
                if (it.mappingServiceRegisterId) {
                    Map<String, Object> mapFieldOut = ec.service.sync().name(it.mappingServiceRegister.serviceName as String)
                        .parameter("srcFieldValue", srcFieldValue)
                        .parameter("dstFieldName", it.dstFieldName as String)
                        .call()
                    if (mapFieldOut.destinationMap) {
                        destinationMap.putAll(mapFieldOut.destinationMap as Map)
                    }
                    if (mapFieldOut.sourceMap) {
                        destinationMap.putAll(mapFieldOut.sourceMap as Map)
                    }
                } else {
                    destinationMap.put(it.dstFieldName as String, srcFieldValue)
                }
            }
        }

        return destinationMap
    }

    @Override
    Object adapt(WebContext context, SessionStore sessionStore, Collection<UserProfile> profiles, Object... parameters) throws Exception {
        if (profiles) {
            for (UserProfile profile : profiles) {
                if (profile.username) {

                    // map profile attributes
                    Timestamp nowTimestamp = ec.user.nowTimestamp
                    EntityValue authFlow = ec.entity.find("moqui.security.sso.AuthFlow")
                            .condition("authFlowId", profile.clientName)
                            .one()
                    Map<String, Object> attributeMap = mapProfileFields(authFlow.fieldMaps as EntityList, profile.attributes)

                    // sync user account
                    String userId
                    EntityValue userAccount = ec.entity.find("moqui.security.UserAccount")
                            .condition("username", profile.username)
                            .useCache(false)
                            .one()
                    if (userAccount) {
                        userId = userAccount.userId
                        ec.service.sync().name("org.moqui.impl.UserServices.update#UserAccount")
                                .parameter("userId", userId)
                                .parameter("externalUserId", profile.id)
                                .parameter("username", profile.username)
                                .parameters(attributeMap)
                                .call()
                    } else {
                        Map createAccountOut = ec.service.sync().name("create#moqui.security.UserAccount")
                                .parameter("externalUserId", profile.id)
                                .parameter("username", profile.username)
                                .parameters(attributeMap)
                                .call()
                        userId = createAccountOut.userId
                    }

                    // find user groups
                    EntityList userGroupMemberList = ec.entity.find("moqui.security.UserGroupMember")
                            .condition("userId", userId)
                            .conditionDate("fromDate", "thruDate", nowTimestamp)
                            .list()
                    Set obsoleteUserGroupIdSet = new HashSet<>(userGroupMemberList*.userGroupId)

                    // sync user groups
                    HashSet<String> roleSet = new HashSet<>()
                    if (profile.roles) {
                        roleSet.addAll(profile.roles)
                    } else if (profile.attributes.containsKey("roles")) {
                        Object rolesObj = profile.attributes.get("roles")
                        if (rolesObj instanceof List) {
                            roleSet.addAll(rolesObj as List)
                        } else if (rolesObj instanceof Set) {
                            roleSet.addAll(rolesObj as Set)
                        }
                    }
                    for (String role : roleSet) {
                        EntityValue roleMap = ec.entity.find("moqui.security.sso.AuthFlowRoleMap")
                                .condition("authFlowId", profile.clientName)
                                .condition("roleName", role)
                                .one()
                        if (roleMap?.userGroupId && !obsoleteUserGroupIdSet.remove(roleMap.userGroupId)) {
                            ec.service.sync().name("create#moqui.security.UserGroupMember")
                                    .parameter("userGroupId", roleMap.userGroupId)
                                    .parameter("userId", userId)
                                    .parameter("fromDate", nowTimestamp)
                                    .call()
                        }
                    }
                    for (EntityValue userGroupMember : userGroupMemberList) {
                        String userGroupId = userGroupMember.userGroupId
                        if (obsoleteUserGroupIdSet.contains(userGroupId) && userGroupId != authFlow.defaultUserGroupId) {
                            ec.service.sync().name("update#moqui.security.UserGroupMember")
                                    .parameter("userGroupId", userGroupId)
                                    .parameter("userId", userId)
                                    .parameter("fromDate", userGroupMember.fromDate)
                                    .parameter("thruDate", nowTimestamp)
                                    .call()
                        }
                    }

                    // add default user group if needed
                    long userGroupCount = ec.entity.find("moqui.security.UserGroupMember")
                            .condition("userId", userId)
                            .conditionDate("fromDate", "thruDate", nowTimestamp)
                            .count()
                    if (userGroupCount == 0) {
                        ec.service.sync().name("create#moqui.security.UserGroupMember")
                                .parameter("userGroupId", authFlow.defaultUserGroupId)
                                .parameter("userId", userId)
                                .parameter("fromDate", nowTimestamp)
                                .call()
                    }
                }
            }
        }

        return null
    }
}
