package org.extvos.auth.shiro;

import org.extvos.common.Validator;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionKey;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.session.mgt.WebSessionManager;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;

/**
 * @author Mingcai SHEN
 */
public class QuickSessionManager extends DefaultWebSessionManager implements WebSessionManager {

    private static final Logger log = LoggerFactory.getLogger(QuickSessionManager.class);

    // Defining constants
    private static final String X_AUTH_TOKEN = "x-auth-token";
    private static final String REFERENCED_SESSION_ID_SOURCE = "Stateless request";

    // Rewriting the constructor
    public QuickSessionManager() {
        super();
        this.setDeleteInvalidSessions(true);
    }

    @Override
    protected void onStart(Session session, SessionContext context) {
        super.onStart(session, context);

        if (!WebUtils.isHttp(context)) {
            log.debug("SessionContext argument is not HTTP compatible or does not have an HTTP request/response " +
                    "pair. No session ID cookie will be set.");
            return;

        }
        HttpServletRequest request = WebUtils.getHttpRequest(context);
        HttpServletResponse response = WebUtils.getHttpResponse(context);

        Serializable sessionId = session.getId();

        if (isSessionIdCookieEnabled()) {
            storeSessionId(sessionId, request, response);
        } else {
            log.debug("Session ID cookie is disabled.  No cookie has been set for new session with id {}", session.getId());
        }
        WebUtils.toHttp(response).setHeader(X_AUTH_TOKEN, sessionId.toString());
        log.trace("Set session ID header for session with id {}", sessionId);
        request.removeAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_IS_NEW, Boolean.TRUE);
    }

    private void storeSessionId(Serializable currentId, HttpServletRequest request, HttpServletResponse response) {
        if (currentId == null) {
            String msg = "sessionId cannot be null when persisting for subsequent requests.";
            throw new IllegalArgumentException(msg);
        }
        Cookie template = getSessionIdCookie();
        Cookie cookie = new SimpleCookie(template);
        String idString = currentId.toString();
        cookie.setValue(idString);
        cookie.saveTo(request, response);
        log.trace("Set session ID cookie for session with id {}", idString);
    }

    /**
     * The rewriting method obtains the token from the request header for interface unification * Shiro will find the value (token) * @ author youcong corresponding to the key authorization from the request header every time the request comes in
     */
    @Override
    public Serializable getSessionId(ServletRequest request, ServletResponse response) {
        String token = WebUtils.toHttp(request).getHeader(X_AUTH_TOKEN);
        //If there is a token in the request header, the token is obtained from the request header
        log.debug("getSessionId:> x-auth-token = {}", token);
        if (Validator.notEmpty(token)) {
            log.debug("getSessionId:> from x-auth-token = {}", token);
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE, REFERENCED_SESSION_ID_SOURCE);
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, token);
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
            return token;
        } else {
            //Take token from cookie according to default rule
            Serializable sessId = super.getSessionId(request, response);
            log.debug("getSessionId:> from cookie = {}", sessId);
            return sessId;
        }
    }


    @Override
    protected void onStop(Session session, SessionKey key) {
        super.onStop(session, key);
        if (WebUtils.isHttp(key)) {
            HttpServletRequest request = WebUtils.getHttpRequest(key);
            HttpServletResponse response = WebUtils.getHttpResponse(key);
            log.debug("Session has been stopped (subject logout or explicit stop).  Removing session ID cookie.");
            removeSessionId(request, response);
        } else {
            log.debug("SessionKey argument is not HTTP compatible or does not have an HTTP request/response " +
                    "pair. Session ID cookie will not be removed due to stopped session.");
        }
    }

    private void removeSessionId(HttpServletRequest request, HttpServletResponse response) {
        getSessionIdCookie().removeFrom(request, response);
    }

}