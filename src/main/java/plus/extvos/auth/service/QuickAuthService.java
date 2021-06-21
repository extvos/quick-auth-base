package plus.extvos.auth.service;

import plus.extvos.auth.dto.PermissionInfo;
import plus.extvos.auth.dto.RoleInfo;
import plus.extvos.auth.dto.UserInfo;
import plus.extvos.restlet.exception.RestletException;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * @author Mingcai SHEN
 */
public interface QuickAuthService {
    /**
     * Get UserInfo by username
     *
     * @param name          : username
     * @param checkEnabled: check if user enabled or not
     * @return UserInfo object
     * @throws RestletException when errors
     */
    UserInfo getUserByName(String name, boolean checkEnabled) throws RestletException;

    /**
     * Get UserInfo by id
     *
     * @param id            of user
     * @param checkEnabled: check if user enabled or not
     * @return UserInfo
     * @throws RestletException when errors
     */
    UserInfo getUserById(Serializable id, boolean checkEnabled) throws RestletException;


    /**
     * Get UserInfo by phone number
     *
     * @param phone        number
     * @param checkEnabled check if user enabled or not
     * @return UserInfo
     * @throws RestletException when errors
     */
    UserInfo getUserByPhone(String phone, boolean checkEnabled) throws RestletException;


    /**
     * Get user roles by id
     *
     * @param id userid
     * @return role list
     * @throws RestletException when errors
     */
    List<RoleInfo> getRoles(Serializable id) throws RestletException;

    /**
     * Get user permissions by id
     *
     * @param id userid
     * @return permission list
     * @throws RestletException when errors
     */
    List<PermissionInfo> getPermissions(Serializable id) throws RestletException;

    /**
     * Create new user info into database or other persistent storage
     *
     * @param username    string
     * @param password    string
     * @param permissions permissions list
     * @param roles       roles list
     * @param params      extra properties of user.
     * @return Serializable user id
     * @throws RestletException when errors
     */
    Serializable createUserInfo(String username, String password, String[] permissions, String[] roles, Map<String, Object> params) throws RestletException;


    /**
     * Update user info into database or other persistent storage
     *
     * @param username    string
     * @param password    string
     * @param permissions permissions list
     * @param roles       roles list
     * @param params      extra properties of user.
     * @throws RestletException when errors
     */
    void updateUserInfo(String username, String password, String[] permissions, String[] roles, Map<String, Object> params) throws RestletException;
}
