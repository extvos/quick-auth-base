package plus.extvos.auth.utils;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import plus.extvos.auth.config.AuthBaseConstant;
import plus.extvos.auth.dto.UserInfo;
import plus.extvos.common.exception.ResultException;

/**
 * @author shenmc
 */
public class SessionUtil {

    /**
     * get current userInfo
     *
     * @return UserInfo if presented or null
     */
    public static UserInfo currentUserInfo() {
        Subject subject = SecurityUtils.getSubject();
        if (null == subject) {
            return null;
        }
        Session session = subject.getSession();
        try {
            return (UserInfo) session.getAttribute(UserInfo.USER_INFO_KEY);
        } catch (ResultException e) {
            return null;
        }
    }

    /**
     * get current username
     *
     * @return String of username of null
     */
    public static String currentUsername() {
        Subject subject = SecurityUtils.getSubject();
        if (null == subject) {
            return null;
        }
        return (String) subject.getPrincipal();
    }

    public static boolean validateCaptcha(String captcha, ResultException... e) throws ResultException {
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        // Need to create session here, when it's first access.
        Session sess = sub.getSession(true);
        if (!captcha.equals(sess.getAttribute(AuthBaseConstant.CAPTCHA_SESSION_KEY))) {
            if (e.length > 0) {
                throw e[0];
            } else {
                return false;
            }
        }
        // Remove it for avoid second use.
        sess.removeAttribute(AuthBaseConstant.CAPTCHA_SESSION_KEY);
        return true;
    }

    public static boolean validateVerifier(String verifier, ResultException... e) throws ResultException {
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        // Need to create session here, when it's first access.
        Session sess = sub.getSession(true);
        if (!verifier.equals(sess.getAttribute(AuthBaseConstant.VERIFIER_SESSION_KEY))) {
            if (e.length > 0) {
                throw e[0];
            } else {
                return false;
            }
        }
        // Remove it for avoid second use.
        sess.removeAttribute(AuthBaseConstant.VERIFIER_SESSION_KEY);
        return true;
    }

    public static void hasRoles(String... roles) throws ResultException {
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        for (String role : roles) {
            if (!sub.hasRole(role)) {
                throw ResultException.forbidden();
            }
        }
    }

    public static void hasAnyRole(String... roles) throws ResultException {
        if (roles.length < 1) {
            return;
        }
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        for (String role : roles) {
            if (sub.hasRole(role)) {
                return;
            }
        }
        throw ResultException.forbidden();
    }

    public static void hasPermissions(String... perms) throws ResultException {
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        for (String perm : perms) {
            if (!sub.isPermitted(perm)) {
                throw ResultException.forbidden();
            }
        }
    }

    public static void hasAnyPermission(String... perms) throws ResultException {
        if (perms.length < 1) {
            return;
        }
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        for (String perm : perms) {
            if (sub.isPermitted(perm)) {
                return;
            }
        }
        throw ResultException.forbidden();
    }

}
