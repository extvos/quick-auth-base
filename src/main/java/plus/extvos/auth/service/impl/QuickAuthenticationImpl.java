package plus.extvos.auth.service.impl;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import plus.extvos.auth.config.AuthBaseConstant;
import plus.extvos.auth.dto.LoginResult;
import plus.extvos.auth.dto.UserInfo;
import plus.extvos.auth.enums.AuthCode;
import plus.extvos.auth.service.QuickAuthentication;
import plus.extvos.auth.service.QuickAuthCallback;
import plus.extvos.auth.service.QuickAuthService;
import plus.extvos.auth.service.UserRegisterHook;
import plus.extvos.auth.shiro.QuickToken;
import plus.extvos.common.Assert;
import plus.extvos.common.exception.ResultException;

@Service
public class QuickAuthenticationImpl implements QuickAuthentication {

    private static final Logger log = LoggerFactory.getLogger(QuickAuthenticationImpl.class);

    @Autowired
    private QuickAuthService quickAuthService;

    @Autowired(required = false)
    private QuickAuthCallback quickAuthCallback;

    @Autowired(required = false)
    private UserRegisterHook userRegisterHook;

    private LoginResult failureResult(int failures, String... errs) {
        LoginResult lr = new LoginResult();
        lr.setFailures(failures);
        if (errs.length > 0) {
            lr.setError(errs[0]);
        }
        return lr;
    }

    @Override
    public LoginResult loginByUsername(String username, String password, String algorithm, String salt, Boolean rememberMe) throws ResultException {
        Assert.notEmpty(username, ResultException.badRequest("username can not be empty"));
        Assert.notEmpty(password, ResultException.badRequest("password can not be empty"));
        return login(username, password, algorithm, salt, null, rememberMe);
    }

    @Override
    public LoginResult loginByEmail(String email, String verifier, Boolean rememberMe) throws ResultException {
        Assert.notEmpty(email, ResultException.badRequest("email can not be empty"));
        Assert.notEmpty(verifier, ResultException.badRequest("verifier can not be empty"));
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        // Need to create session here, when it's first access.
        Session sess = sub.getSession(true);
        Integer fn = (Integer) sess.getAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT);
        if (null == fn) {
            fn = 0;
        }
        UserInfo userInfo = quickAuthService.getUserByEmail(email, true);
        if (null == userInfo) {
            sess.setAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT, fn + 1);
            throw new ResultException(AuthCode.ACCOUNT_NOT_FOUND, "user with email <" + email + "> not found", failureResult(fn + 1));
        }
        if (!verifier.equals(sess.getAttribute(AuthBaseConstant.VERIFIER_SESSION_KEY))) {
            log.error("doLogin:> [{}] 验证码错误", email);
            throw new ResultException(AuthCode.INCORRECT_VERIFIER, "incorrect verifier", failureResult(fn + 1));
        }
        return loginImplicitly(userInfo, rememberMe);
    }

    @Override
    public LoginResult loginByEmail(String email, String password, String algorithm, String salt, Boolean rememberMe) throws ResultException {
        Assert.notEmpty(email, ResultException.badRequest("email can not be empty"));
        Assert.notEmpty(password, ResultException.badRequest("password can not be empty"));
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        // Need to create session here, when it's first access.
        Session sess = sub.getSession(true);
        Integer fn = (Integer) sess.getAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT);
        if (null == fn) {
            fn = 0;
        }
        UserInfo userInfo = quickAuthService.getUserByEmail(email, true);
        if (null == userInfo) {
            sess.setAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT, fn + 1);
            throw new ResultException(AuthCode.ACCOUNT_NOT_FOUND, "user with email <" + email + "> not found", failureResult(fn + 1));
        }
        return login(userInfo.getUsername(), password, algorithm, salt, userInfo, rememberMe);
    }

    @Override
    public LoginResult loginByCellphone(String cellphone, String verifier, Boolean rememberMe) throws ResultException {
        Assert.notEmpty(cellphone, ResultException.badRequest("cellphone can not be empty"));
        Assert.notEmpty(verifier, ResultException.badRequest("verifier can not be empty"));
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        // Need to create session here, when it's first access.
        Session sess = sub.getSession(true);
        Integer fn = (Integer) sess.getAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT);
        if (null == fn) {
            fn = 0;
        }
        UserInfo userInfo = quickAuthService.getUserByPhone(cellphone, true);
        if (null == userInfo) {
            sess.setAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT, fn + 1);
            throw new ResultException(AuthCode.ACCOUNT_NOT_FOUND, "user with cellphone <" + cellphone + "> not found", failureResult(fn + 1));
        }
        if (!verifier.equals(sess.getAttribute(AuthBaseConstant.VERIFIER_SESSION_KEY))) {
            log.error("doLogin:> [{}] 验证码错误", cellphone);
            throw new ResultException(AuthCode.INCORRECT_VERIFIER, "incorrect verifier", failureResult(fn + 1));
        }
        return loginImplicitly(userInfo, rememberMe);
    }

    @Override
    public LoginResult loginByCellphone(String cellphone, String password, String algorithm, String salt, Boolean rememberMe) throws ResultException {
        Assert.notEmpty(cellphone, ResultException.badRequest("cellphone can not be empty"));
        Assert.notEmpty(password, ResultException.badRequest("password can not be empty"));
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        // Need to create session here, when it's first access.
        Session sess = sub.getSession(true);
        Integer fn = (Integer) sess.getAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT);
        if (null == fn) {
            fn = 0;
        }
        UserInfo userInfo = quickAuthService.getUserByPhone(cellphone, true);
        if (null == userInfo) {
            sess.setAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT, fn + 1);
            throw new ResultException(AuthCode.ACCOUNT_NOT_FOUND, "user with cellphone <" + cellphone + "> not found", failureResult(fn + 1));
        }
        return login(userInfo.getUsername(), password, algorithm, salt, userInfo, rememberMe);
    }

    private LoginResult login(String username, String password, String algorithm, String salt, UserInfo userInfo, Boolean rememberMe) {
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        // Need to create session here, when it's first access.
        Session sess = sub.getSession(true);
        Integer fn = (Integer) sess.getAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT);
        if (null == fn) {
            fn = 0;
        }
        // Perform the login
        QuickToken token = new QuickToken(username, password, algorithm, salt);
        if (null != rememberMe && rememberMe) {
            token.setRememberMe(true);
        }
        try {
            sub.login(token);
            if (null == userInfo) {
                userInfo = quickAuthService.getUserByName(username, false);
            }
            userInfo = quickAuthService.fillUserInfo(userInfo);
            if (null != quickAuthCallback) {
                userInfo = quickAuthCallback.onLoggedIn(userInfo);
            }
            sess.setAttribute(UserInfo.USER_INFO_KEY, userInfo);
            userInfo.setPassword("*******");
            LoginResult lr = new LoginResult(token.getUsername(), sess.getId(), null, null, userInfo);
            lr.setRemembered(token.isRememberMe());
            sess.removeAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT);
            return lr;
        } catch (UnknownAccountException e) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,用户不存在", username);
            token.clear();
            sess.setAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT, fn + 1);
//            return failureResult(fn + 1),"").failure();
            return failureResult(fn + 1, "用户不存在");
        } catch (LockedAccountException lae) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,账户已锁定", username);
            token.clear();
            sess.setAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT, fn + 1);
            return failureResult(fn + 1, "账户已锁定");
        } catch (DisabledAccountException lae) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,账户未启用", username);
            token.clear();
            sess.setAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT, fn + 1);
            return failureResult(fn + 1, "账户未启用");
        } catch (ExcessiveAttemptsException e) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,错误次数过多", username);
            token.clear();
            sess.setAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT, fn + 1);
            return failureResult(fn + 1, "错误次数过");
        } catch (CredentialsException e) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,密码或用户名错误", username);
            token.clear();
            sess.setAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT, fn + 1);
            return failureResult(fn + 1, "密码或用户名错误");
        } catch (AuthenticationException e) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,堆栈轨迹如下", username, e);
            token.clear();
            sess.setAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT, fn + 1);
            return failureResult(fn + 1, "密码或用户名错误");
        } catch (Exception e) {
            sess.setAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT, fn + 1);
            return failureResult(fn + 1, e.getMessage());
        }
    }

    @Override
    public LoginResult loginImplicitly(UserInfo userInfo, Boolean rememberMe) {
        return login(userInfo.getUsername(), userInfo.getPassword(), "", "", userInfo, rememberMe);
    }

    @Override
    public void logout() throws ResultException {
        try {
            Subject subject = SecurityUtils.getSubject();
            log.debug("doLogout:> {} logout ...", subject.getPrincipal());
            subject.logout();
            if (null != quickAuthCallback) {
                quickAuthCallback.onLogout(userInfo());
            }
        } catch (Exception e) {
            log.warn("doLogout:> failed: ", e);
        }
    }

    @Override
    public UserInfo userInfo(String sessionId) {
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        // Need to create session here, when it's first access.
        Session sess = sub.getSession(true);
        return (UserInfo) sess.getAttribute(UserInfo.USER_INFO_KEY);

    }

    @Override
    public UserInfo userInfo() {
        return userInfo(null);
    }

    @Override
    public void updateUserInfo(UserInfo userInfo) throws ResultException {
        updateUserInfo(null, userInfo);
    }

    @Override
    public void updateUserInfo(String sessionId, UserInfo userInfo) throws ResultException {
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        // Need to create session here, when it's first access.
        Session sess = sub.getSession(true);
        UserInfo orig = userInfo(sessionId);
        if (userInfo.getExtraInfo() != null) {
            orig.setExtraInfo(userInfo.getExtraInfo());
        }
        if (userInfo.getRoles() != null) {
            orig.setRoles(userInfo.getRoles());
        }
        if (userInfo.getPermissions() != null) {
            orig.setPermissions(userInfo.getPermissions());
        }
        if (userInfo.getProvider() != null) {
            orig.setProvider(userInfo.getProvider());
        }
        if (userInfo.getOpenId() != null) {
            orig.setOpenId(userInfo.getOpenId());
        }
        sess.setAttribute(UserInfo.USER_INFO_KEY, orig);
    }

    @Override
    public void validateCaptcha(String captcha, boolean enabled) throws ResultException {
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        // Need to create session here, when it's first access.
        Session sess = sub.getSession(true);
        Integer fn = (Integer) sess.getAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT);
        if (null == fn) {
            fn = 0;
        }
        if (captcha != null && !captcha.isEmpty()) {
            if (!captcha.equals(sess.getAttribute(AuthBaseConstant.CAPTCHA_SESSION_KEY))) {
                log.error("doLogin:> [{},{}] 验证码错误", captcha, sess.getAttribute(AuthBaseConstant.CAPTCHA_SESSION_KEY));
                sess.setAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT, fn + 1);
                throw new ResultException(AuthCode.INCORRECT_CAPTCHA, "invalid captcha", failureResult(fn + 1));
            }
            // Remove it for avoid second use.
            sess.removeAttribute(AuthBaseConstant.CAPTCHA_SESSION_KEY);
        } else if (enabled) {
            log.error("doLogin:> [{},{}] 验证码未提供", captcha, sess.getAttribute(AuthBaseConstant.CAPTCHA_SESSION_KEY));
            sess.setAttribute(AuthBaseConstant.FAILURE_SESSION_COUNT, fn + 1);
            throw new ResultException(AuthCode.INCORRECT_CAPTCHA, "captcha required", failureResult(fn + 1));
        }
    }
}
