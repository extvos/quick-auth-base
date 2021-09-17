package plus.extvos.auth.utils;

import plus.extvos.auth.dto.UserInfo;
import plus.extvos.common.exception.ResultException;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;

/**
 * @author shenmc
 */
public class SessionUtil {

    /**
     * get current userInfo
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
     * @return String of username of null
     */
    public static String currentUsername() {
        Subject subject = SecurityUtils.getSubject();
        if (null == subject) {
            return null;
        }
        return (String) subject.getPrincipal();
    }

}
