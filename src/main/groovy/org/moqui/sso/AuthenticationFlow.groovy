package org.moqui.sso

import org.moqui.context.ExecutionContext
import org.moqui.impl.context.UserFacadeImpl
import org.pac4j.core.authorization.authorizer.DefaultAuthorizers
import org.pac4j.core.client.Client
import org.pac4j.core.config.Config
import org.pac4j.core.engine.DefaultCallbackLogic
import org.pac4j.core.engine.DefaultLogoutLogic
import org.pac4j.core.engine.DefaultSecurityLogic
import org.pac4j.core.profile.ProfileManager
import org.pac4j.core.profile.UserProfile
import org.pac4j.jee.context.JEEContext
import org.pac4j.jee.context.session.JEESessionStore
import org.pac4j.jee.http.adapter.JEEHttpActionAdapter
import org.pac4j.saml.state.SAML2StateGenerator

class AuthenticationFlow {

    /**
     * Performs a login operation.
     */
    static void loginUser(ExecutionContext ec) {

        // parameters
        String authFlowId = ec.context.get("authFlowId") as String
        String returnTo = ec.context.get("returnTo") as String
        String baseUrl = ec.web.getWebappRootUrl(true, false)
        String callbackUrl = baseUrl + "/sso/callback"

        // init fields required for logic
        JEEContext context = new JEEContext(ec.web.request, ec.web.response)
        JEESessionStore sessionStore = JEESessionStore.INSTANCE
        MoquiSecurityGrantedAccessAdapter securityGrantedAccessAdapter = new MoquiSecurityGrantedAccessAdapter(ec)
        JEEHttpActionAdapter actionAdapter = JEEHttpActionAdapter.INSTANCE

        // store return URL
        if (returnTo) {
            ec.web.sessionAttributes.put("moquiAuthFlowReturnTo", returnTo)
            sessionStore.set(context, SAML2StateGenerator.SAML_RELAY_STATE_ATTRIBUTE, returnTo)
        }

        // init config
        Client client = new AuthenticationClientFactory(ec).build(authFlowId)
        Config config = new Config(callbackUrl, client)

        // perform logic
        try {
            DefaultSecurityLogic.INSTANCE.perform(
                    context,
                    sessionStore,
                    config,
                    securityGrantedAccessAdapter,
                    actionAdapter,
                    authFlowId,
                    DefaultAuthorizers.IS_AUTHENTICATED,
                    null
            )
        } catch (RuntimeException e) {
            ec.logger.error("An error occurred while performing login action", e)
            ec.web.response.sendRedirect(baseUrl + "/Login")
        }
    }

    /**
     * Handles the login callback.
     */
    static void handleCallback(ExecutionContext ec) {

        // parameters
        String baseUrl = ec.web.getWebappRootUrl(true, false)

        // init fields required for logic
        JEEContext context = new JEEContext(ec.web.request, ec.web.response)
        JEESessionStore sessionStore = JEESessionStore.INSTANCE
        MoquiSecurityGrantedAccessAdapter securityGrantedAccessAdapter = new MoquiSecurityGrantedAccessAdapter(ec)
        JEEHttpActionAdapter actionAdapter = JEEHttpActionAdapter.INSTANCE

        // init config
        Config config = new Config(ec.web.getWebappRootUrl(true, false) + "/sso/callback", new org.moqui.sso.AuthenticationClientFactory(ec).buildAll())

        // retrieve return URL from "RelayState" parameter (SAML only), or from session attribute
        String redirectTo = context.getRequestParameter("RelayState").orElse(ec.web.sessionAttributes.moquiAuthFlowReturnTo as String)

        // perform logic
        try {
            DefaultCallbackLogic.INSTANCE.perform(
                    context,
                    sessionStore,
                    config,
                    actionAdapter,
                    null,
                    false,
                    null
            )

            // handle incoming profiles
            ProfileManager profileManager = new ProfileManager(context, sessionStore)
            securityGrantedAccessAdapter.adapt(context, sessionStore, profileManager.getProfiles())

            // login user
            Optional<UserProfile> optionalProfile = profileManager.getProfile()
            if (optionalProfile.isPresent()) {
                UserProfile profile = optionalProfile.get()
                ((UserFacadeImpl) ec.user).internalLoginUser(profile.username)
                ec.web.sessionAttributes.put("moquiAuthFlowExternalLogout", true)
                ec.web.sessionAttributes.put("moquiAuthFlowReturnTo", redirectTo)
            }
        } catch (RuntimeException e) {
            ec.logger.error("An error occurred while handling callback", e)
            ec.web.response.sendRedirect(baseUrl + "/Login")
        }
    }

    /**
     * Performs a logout operation.
     */
    static void logoutUser(ExecutionContext ec) {

        // parameters
        String returnTo = ec.context.get("returnTo") as String
        String baseUrl = ec.web.getWebappRootUrl(true, false)
        String callbackUrl = returnTo ?: baseUrl + "/Login"

        // init fields required for logic
        JEEContext context = new JEEContext(ec.web.request, ec.web.response)
        JEESessionStore sessionStore = JEESessionStore.INSTANCE
        JEEHttpActionAdapter actionAdapter = JEEHttpActionAdapter.INSTANCE

        // init config
        Config config = new Config(baseUrl + "/sso/callback", new AuthenticationClientFactory(ec).buildAll())

        // perform logic
        try {
            DefaultLogoutLogic.INSTANCE.perform(
                    context,
                    sessionStore,
                    config,
                    actionAdapter,
                    callbackUrl,
                    null,
                    false,
                    false,
                    true
            )

            // logout user
            ec.user.logoutUser()
        } catch (RuntimeException e) {
            ec.logger.error("An error occurred while performing logout action", e)
            ec.web.response.sendRedirect(returnTo ?: baseUrl + "/Login")
        }
    }
}
