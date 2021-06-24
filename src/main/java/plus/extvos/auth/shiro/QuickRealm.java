package plus.extvos.auth.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;
import plus.extvos.auth.dto.PermissionInfo;
import plus.extvos.auth.dto.RoleInfo;
import plus.extvos.auth.dto.UserInfo;
import plus.extvos.auth.enums.AuthCode;
import plus.extvos.auth.service.QuickAuthService;
import plus.extvos.restlet.exception.RestletException;
import plus.extvos.restlet.utils.SpringContextHolder;

/**
 * @author Mingcai SHEN
 */
public class QuickRealm extends AuthorizingRealm {

    private static final Logger log = LoggerFactory.getLogger(QuickRealm.class);

    @Autowired
    private QuickAuthService quickAuthService;

    @Override
    public boolean supports(AuthenticationToken token) {
        if (null == quickAuthService) {
            log.warn("supports: quickAuthService == null ");
            quickAuthService = SpringContextHolder.getBean(QuickAuthService.class);
        }
        return token instanceof QuickToken;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        log.debug("doGetAuthorizationInfo: {}", principalCollection.getClass().toString());
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        log.debug("doGetAuthorizationInfo:> session: {}", session.getId());
        //获取登录用户名
        String name = (String) principalCollection.getPrimaryPrincipal();
        log.debug("doGetAuthorizationInfo> name = {}", name);
        //查询用户名称
        try {
            Object obj = getCacheManager().getCache("simpleAuthorizationInfo").get(name);
            if (obj instanceof SimpleAuthorizationInfo) {
                return (SimpleAuthorizationInfo) obj;
            }
            UserInfo user = quickAuthService.getUserByName(name, true);
            if (null == user) {
                log.debug("doGetAuthorizationInfo> can not get user by username {}", name);
                return null;
            }
            //添加角色和权限
            SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();

            for (RoleInfo role : quickAuthService.getRoles(user.getUserId())) {
                //添加角色
                simpleAuthorizationInfo.addRole(role.getCode());
            }
            //添加权限
            for (PermissionInfo permission : quickAuthService.getPermissions(user.getUserId())) {
                simpleAuthorizationInfo.addStringPermission(permission.getCode());
            }
            return simpleAuthorizationInfo;
        } catch (Exception e) {
            log.error("doGetAuthorizationInfo>", e);
            return null;
        }

    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        log.debug("doGetAuthenticationInfo: {}", authenticationToken.getClass().toString());
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        log.debug("doGetAuthenticationInfo:> session: {}", session.getId());
        if (!StringUtils.hasText(authenticationToken.getPrincipal().toString())) {
            log.warn("doGetAuthenticationInfo:> invalid token with empty principal !");
            return null;
        }
        String username = authenticationToken.getPrincipal().toString();
        log.debug("doGetAuthenticationInfo> try username = {}", username);
        try {
            UserInfo userInfo = quickAuthService.getUserByName(username, true);
            if (userInfo == null) {
                //这里返回后会报出对应异常
                log.warn("doGetAuthenticationInfo> can not get user by username {}", username);
                return null;
            } else {
                //这里验证authenticationToken和simpleAuthenticationInfo的信息
                log.debug("doGetAuthenticationInfo> got user by username {}", userInfo);
                return new QuickInfo(userInfo);
            }
        } catch (RestletException e) {
            log.error("doGetAuthenticationInfo 1>", e);
            if (AuthCode.ACCOUNT_NOT_FOUND.equals(e.getCode())) {
                throw new CredentialsException(e.getMessage());
            } else if (AuthCode.ACCOUNT_DISABLED.equals(e.getCode())) {
                throw new DisabledAccountException(e.getMessage());
            } else if (AuthCode.ACCOUNT_LOCKED.equals(e.getCode())) {
                throw new LockedAccountException(e.getMessage());
            } else {
                throw new UnknownAccountException(e.getMessage());
            }
        } catch (Exception e) {
            log.error("doGetAuthenticationInfo 2>", e);
            return null;
        }
    }
}
