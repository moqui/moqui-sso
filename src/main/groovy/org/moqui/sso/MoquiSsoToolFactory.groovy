package org.moqui.sso

import org.moqui.context.ExecutionContext
import org.moqui.context.ExecutionContextFactory
import org.moqui.context.ToolFactory
import org.moqui.security.SingleSignOnTokenLoginHandler
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class MoquiSsoToolFactory implements ToolFactory<SingleSignOnTokenLoginHandler>{
    protected final static Logger logger = LoggerFactory.getLogger(MoquiSsoToolFactory.class)
    final static String TOOL_NAME = "MoquiSso"

    protected ExecutionContextFactory ecf = null

    protected SingleSignOnTokenLoginHandler ssoTokenLoginHandler = null

    @Override
    String getName() { return TOOL_NAME }
    @Override
    void init(ExecutionContextFactory ecf) { }
    @Override
    void preFacadeInit(ExecutionContextFactory ecf) { }
    @Override
    SingleSignOnTokenLoginHandler getInstance(Object... parameters) {
        if (ssoTokenLoginHandler == null)
            ssoTokenLoginHandler = new SsoTokenLoginHandler()
        return ssoTokenLoginHandler
    }

    @Override
    void destroy() { }

    @Override
    void postFacadeDestroy() { }

    class SsoTokenLoginHandler implements SingleSignOnTokenLoginHandler {
        @Override
        boolean handleSsoLoginToken(ExecutionContext ec, HttpServletRequest request, HttpServletResponse response, String ssoAccessToken, String ssoAuthFlowId) {
            return AuthenticationFlow.handleSwtLogin(ec, request, response, ssoAccessToken, ssoAuthFlowId)
        }
    }
}
