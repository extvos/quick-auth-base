package plus.extvos.auth.service;

import plus.extvos.auth.dto.PermissionInfo;
import plus.extvos.auth.dto.RoleInfo;
import plus.extvos.auth.dto.UserInfo;
import plus.extvos.common.exception.ResultException;

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
     * @param name         username
     * @param checkEnabled check if user enabled or not
     * @return UserInfo object
     * @throws ResultException when errors
     */
    UserInfo getUserByName(String name, boolean checkEnabled) throws ResultException;

    /**
     * Get UserInfo by id
     *
     * @param id            of user
     * @param checkEnabled check if user enabled or not
     * @return UserInfo
     * @throws ResultException when errors
     */
    UserInfo getUserById(Serializable id, boolean checkEnabled) throws ResultException;


    /**
     * Get UserInfo by phone number
     *
     * @param phone        number
     * @param checkEnabled check if user enabled or not
     * @return UserInfo
     * @throws ResultException when errors
     */
    UserInfo getUserByPhone(String phone, boolean checkEnabled) throws ResultException;


    /**
     * Get UserInfo by email address
     *
     * @param email        email address
     * @param checkEnabled check if user enabled or not
     * @return UserInfo
     * @throws ResultException when errors
     */
    UserInfo getUserByEmail(String email, boolean checkEnabled) throws ResultException;


    /**
     * Get user roles by id
     *
     * @param id userid
     * @return role list
     * @throws ResultException when errors
     */
    List<RoleInfo> getRoles(Serializable id) throws ResultException;

    /**
     * Get user permissions by id
     *
     * @param id userid
     * @return permission list
     * @throws ResultException when errors
     */
    List<PermissionInfo> getPermissions(Serializable id) throws ResultException;

    /**
     * Fill userInfo object with more details like roles, permissions etc...
     *
     * @param userInfo original userInfo
     * @return new filled userInfo
     * @throws ResultException when error
     */
    UserInfo fillUserInfo(UserInfo userInfo) throws ResultException;

    /**
     * Create new user info into database or other persistent storage
     *
     * @param username    string
     * @param password    string
     * @param status      short
     * @param permissions permissions list
     * @param roles       roles list
     * @param params      extra properties of user.
     * @return Serializable user id
     * @throws ResultException when errors
     */
    Serializable createUserInfo(String username, String password, short status, String[] permissions, String[] roles, Map<String, Object> params) throws ResultException;


    /**
     * Update user info into database or other persistent storage
     *
     * @param username    string
     * @param password    string
     * @param permissions permissions list
     * @param roles       roles list
     * @param params      extra properties of user.
     * @throws ResultException when errors
     */
    void updateUserInfo(String username, String password, String[] permissions, String[] roles, Map<String, Object> params) throws ResultException;
}
