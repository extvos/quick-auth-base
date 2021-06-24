package plus.extvos.auth.shiro;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import plus.extvos.auth.config.QuickAuthConfig;
import plus.extvos.restlet.RestletCode;
import plus.extvos.restlet.Result;
import plus.extvos.restlet.utils.SpringContextHolder;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Mingcai SHEN
 */
public class QuickFilter extends AuthenticatingFilter {

    private static final Logger log = LoggerFactory.getLogger(QuickFilter.class);

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        log.debug("isAccessAllowed");
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        log.debug("isAccessAllowed:> session: {}", session != null ? session.getId() : "empty");
        return super.isAccessAllowed(request, response, mappedValue);
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        log.debug("onAccessDenied:> {}", ((HttpServletRequest) request).getRequestURI());
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        log.debug("onAccessDenied:> session: {}", session != null ? session.getId() : "empty");
        if (subject.isAuthenticated()) {
            return true;
        }
        QuickAuthConfig cfg = SpringContextHolder.getBean(QuickAuthConfig.class);
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setCharacterEncoding("UTF-8");
        httpResponse.setStatus(RestletCode.UNAUTHORIZED.status());
        ObjectMapper om = new ObjectMapper();
        httpResponse.getWriter().print(om.writeValueAsString(Result.message("Logging Required").failure(RestletCode.UNAUTHORIZED)));

        return false;
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        log.debug("createToken::1");
        QuickAuthConfig cfg = SpringContextHolder.getBean(QuickAuthConfig.class);
        return new QuickToken((HttpServletRequest) request, cfg.getSecret());
    }


    @Override
    protected AuthenticationToken createToken(String username, String password, ServletRequest request, ServletResponse response) {
        log.debug("createToken::2");
        boolean rememberMe = this.isRememberMe(request);
        String host = this.getHost(request);
        return this.createToken(username, password, rememberMe, host);
    }

    @Override
    protected AuthenticationToken createToken(String username, String password, boolean rememberMe, String host) {
        log.debug("createToken::3");
        return new QuickToken(username, password, "md5", null);
    }
}
