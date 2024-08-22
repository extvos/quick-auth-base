package plus.extvos.auth.service;

import plus.extvos.auth.dto.LoginResult;
import plus.extvos.auth.dto.UserInfo;
import plus.extvos.common.exception.ResultException;

import java.util.Map;

/**
 * BaseAuthService
 * <p>
 * User login and logout process;
 * Register process
 */
public interface QuickAuthentication {
    LoginResult loginByUsername(String username, String password, String algorithm, String salt, Boolean rememberMe, Map<String, String> params) throws ResultException;

    LoginResult loginByEmail(String email, String verifier, Boolean rememberMe, Map<String, String> params) throws ResultException;

    LoginResult loginByEmail(String email, String password, String algorithm, String salt, Boolean rememberMe, Map<String, String> params) throws ResultException;

    LoginResult loginByCellphone(String cellphone, String verifier, Boolean rememberMe, Map<String, String> params) throws ResultException;

    LoginResult loginByCellphone(String cellphone, String password, String algorithm, String salt, Boolean rememberMe, Map<String, String> params) throws ResultException;

    // login with username,password, algorithm, salt
    LoginResult loginImplicitly(UserInfo userInfo, Boolean rememberMe, Map<String, String> params) throws ResultException;

    void logout() throws ResultException;

    UserInfo userInfo(String sessionId);

    UserInfo userInfo();

    void updateUserInfo(UserInfo userInfo) throws ResultException;

    void updateUserInfo(String sessionId, UserInfo userInfo) throws ResultException;

    void validateCaptcha(String captcha, boolean enabled) throws ResultException;
}
