package org.moqui.sso

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import org.moqui.context.ExecutionContext
import org.moqui.entity.EntityList
import org.moqui.entity.EntityValue
import org.moqui.resource.ResourceReference
import org.pac4j.core.client.Client
import org.pac4j.oauth.client.*
import org.pac4j.oidc.client.*
import org.pac4j.oidc.config.AppleOidcConfiguration
import org.pac4j.oidc.config.AzureAd2OidcConfiguration
import org.pac4j.oidc.config.KeycloakOidcConfiguration
import org.pac4j.oidc.config.OidcConfiguration
import org.pac4j.saml.client.SAML2Client
import org.pac4j.saml.config.SAML2Configuration
import org.springframework.core.io.FileSystemResource

/**
 * Builds clients for desired authentication flows.
 */
final class AuthenticationClientFactory {

    /**
     * Execution context used to access facades.
     */
    private ExecutionContext ec

    /**
     * Initializes a new {@code AuthenticationClientFactory}.
     */
    AuthenticationClientFactory(ExecutionContext ec) {
        this.ec = ec
    }

    /**
     * Builds a client specific to the specified flow.
     */
    Client build(String authFlowId) {

        // find auth flow
        EntityValue authFlow = ec.entity.find("moqui.security.sso.AuthFlow")
                .condition("authFlowId", authFlowId)
                .one()

        // build client
        if ("AftOidc" == authFlow.authFlowTypeEnumId) {
            return buildOidcClient(authFlowId)
        } else if ("AftOauth" == authFlow.authFlowTypeEnumId) {
            return buildOauthClient(authFlowId)
        } else if ("AftSaml" == authFlow.authFlowTypeEnumId) {
            return buildSamlClient(authFlowId)
        } else {
            return null
        }
    }

    /**
     * Builds a client specific to the specified auth flow.
     */
    List<Client> buildAll() {
        EntityList authFlowList = ec.entity.find("moqui.security.sso.AuthFlow").list()
        List clientList = []
        for (EntityValue authFlow : authFlowList) {
            if ("Y" != authFlow.disabled && "Y" != authFlow.inbound) {
                clientList.add(build((String) authFlow.authFlowId))
            }
        }
        return clientList
    }

    private Client buildOidcClient(String authFlowId) {

        // find auth flow
        EntityValue authFlow = ec.entity.find("moqui.security.sso.OidcFlow")
                .condition("authFlowId", authFlowId)
                .one()

        // init client
        OidcConfiguration config
        OidcClient client
        if ("OctApple" == authFlow.clientTypeEnumId) {
            config = new AppleOidcConfiguration()
            client = new AppleClient(config)
        } else if ("OctAzureAd" == authFlow.clientTypeEnumId) {
            config = new AzureAd2OidcConfiguration()
            client = new AzureAd2Client(config)
        } else if ("OctGoogle" == authFlow.clientTypeEnumId) {
            config = new OidcConfiguration()
            client = new GoogleOidcClient(config)
        } else if ("OctKeycloak" == authFlow.clientTypeEnumId) {
            config = new KeycloakOidcConfiguration()
            config.setRealm(authFlow.realm as String)
            config.setBaseUri(authFlow.baseUri as String)
            client = new KeycloakOidcClient(config)
        } else {
            config = new OidcConfiguration()
            client = new OidcClient(config)
        }

        // common configuration settings
        config.setClientId(authFlow.clientId as String)
        config.setSecret(authFlow.secret as String)
        config.setDiscoveryURI(authFlow.discoveryUri as String)
        config.setClientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        config.setPreferredJwsAlgorithmAsString(authFlow.preferredJwsAlgorithm.optionValue as String)
        config.setUseNonce("Y" == authFlow.useNonce)

        // common client settings
        client.setName(authFlowId)

        return client
    }

    private Client buildOauthClient(String authFlowId) {

        // find auth flow
        EntityValue authFlow = ec.entity.find("moqui.security.sso.OauthFlow")
                .condition("authFlowId", authFlowId)
                .one()

        // init client
        if ("OctBitBucket" == authFlow.clientTypeEnumId) {
            BitbucketClient client = new BitbucketClient()
            client.setKey(authFlow.clientId as String)
            client.setSecret(authFlow.secret as String)
            client.setName(authFlowId)
            return client
        } else if ("OctDropBox" == authFlow.clientTypeEnumId) {
            DropBoxClient client = new DropBoxClient()
            client.setKey(authFlow.clientId as String)
            client.setSecret(authFlow.secret as String)
            client.setName(authFlowId)
            return client
        } else if ("OctFacebook" == authFlow.clientTypeEnumId) {
            FacebookClient client = new FacebookClient()
            client.setKey(authFlow.clientId as String)
            client.setSecret(authFlow.secret as String)
            client.setName(authFlowId)
            return client
        } else if ("OctFoursquare" == authFlow.clientTypeEnumId) {
            FoursquareClient client = new FoursquareClient()
            client.setKey(authFlow.clientId as String)
            client.setSecret(authFlow.secret as String)
            client.setName(authFlowId)
            return client
        } else if ("OctGitHub" == authFlow.clientTypeEnumId) {
            GitHubClient client = new GitHubClient()
            client.setKey(authFlow.clientId as String)
            client.setSecret(authFlow.secret as String)
            client.setName(authFlowId)
            return client
        } else if ("OctGoogle" == authFlow.clientTypeEnumId) {
            Google2Client client = new Google2Client()
            client.setKey(authFlow.clientId as String)
            client.setSecret(authFlow.secret as String)
            client.setName(authFlowId)
            return client
        } else if ("OctLinkedIn" == authFlow.clientTypeEnumId) {
            LinkedIn2Client client = new LinkedIn2Client()
            client.setKey(authFlow.clientId as String)
            client.setSecret(authFlow.secret as String)
            client.setName(authFlowId)
            return client
        } else if ("OctPaypal" == authFlow.clientTypeEnumId) {
            PayPalClient client = new PayPalClient()
            client.setKey(authFlow.clientId as String)
            client.setSecret(authFlow.secret as String)
            client.setName(authFlowId)
            return client
        } else if ("OctTwitter" == authFlow.clientTypeEnumId) {
            TwitterClient client = new TwitterClient()
            client.setKey(authFlow.clientId as String)
            client.setSecret(authFlow.secret as String)
            client.setName(authFlowId)
            return client
        } else if ("OctWordPress" == authFlow.clientTypeEnumId) {
            WordPressClient client = new WordPressClient()
            client.setKey(authFlow.clientId as String)
            client.setSecret(authFlow.secret as String)
            client.setName(authFlowId)
            return client
        } else if ("OctYahoo" == authFlow.clientTypeEnumId) {
            YahooClient client = new YahooClient()
            client.setKey(authFlow.clientId as String)
            client.setSecret(authFlow.secret as String)
            client.setName(authFlowId)
            return client
        } else if ("OctOauth10" == authFlow.clientTypeEnumId) {
            OAuth10Client client = new OAuth10Client()
            client.setKey(authFlow.clientId as String)
            client.setSecret(authFlow.secret as String)
            client.setName(authFlowId)
            return client
        } else if ("OctOauth20" == authFlow.clientTypeEnumId) {
            OAuth20Client client = new OAuth20Client()
            client.setKey(authFlow.clientId as String)
            client.setSecret(authFlow.secret as String)
            client.setName(authFlowId)
            return client
        }

        return null
    }

    private Client buildSamlClient(String authFlowId) {

        // find auth flow
        EntityValue authFlow = ec.entity.find("moqui.security.sso.SamlFlow")
                .condition("authFlowId", authFlowId)
                .one()

        // copy keystore to tmp directory
        ResourceReference keystoreLocationRef = ec.resource.getLocationReference(authFlow.keystoreLocation as String)
        ResourceReference keystoreTempRef = ec.resource.getLocationReference(ec.factory.runtimePath + "/tmp/" + keystoreLocationRef.getFileName())
        keystoreTempRef.putStream(keystoreLocationRef.openStream())

        // copy metadata to tmp directory
        ResourceReference metadataLocationRef = ec.resource.getLocationReference(authFlow.identityProviderMetadataLocation as String)
        ResourceReference metadataTempRef = ec.resource.getLocationReference(ec.factory.runtimePath + "/tmp/" + metadataLocationRef.getFileName())
        metadataTempRef.putStream(metadataLocationRef.openStream())

        // init client
        SAML2Configuration config = new SAML2Configuration(
                new FileSystemResource(new File(keystoreTempRef.getUri())),
                authFlow.keystorePassword as String,
                authFlow.privateKeyPassword as String,
                new FileSystemResource(new File(metadataTempRef.getUri()))
        )
        config.setServiceProviderEntityId(authFlow.serviceProviderEntityId as String)
        config.setForceAuth("Y" == authFlow.forceAuth)
        config.setPassive("Y" == authFlow.passive)
        SAML2Client client = new SAML2Client(config)
        client.setName(authFlowId)

        return client
    }
}
