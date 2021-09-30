package plus.extvos.auth.service;

import plus.extvos.auth.dto.UserInfo;
import plus.extvos.common.exception.ResultException;

/**
 * @author shenmc
 */
public interface QuickAuthCallback {
    /**
     * On logged in callback
     *
     * @param userInfo of current user
     * @return UserInfo if updated
     * @throws ResultException when error
     */
    UserInfo onLoggedIn(UserInfo userInfo) throws ResultException;

    /**
     * On Logout call back
     *
     * @param userInfo of current user
     * @throws ResultException when error
     */
    void onLogout(UserInfo userInfo) throws ResultException;
}
