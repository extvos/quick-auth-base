package plus.extvos.auth.controller;

import com.google.code.kaptcha.Producer;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import plus.extvos.auth.annotation.SessionUser;
import plus.extvos.auth.config.QuickAuthConfig;
import plus.extvos.auth.dto.CheckResult;
import plus.extvos.auth.dto.LoginResult;
import plus.extvos.auth.dto.UserInfo;
import plus.extvos.auth.enums.AuthCode;
import plus.extvos.auth.service.QuickAuthCallback;
import plus.extvos.auth.service.QuickAuthService;
import plus.extvos.auth.service.SMSService;
import plus.extvos.auth.service.UserRegisterHook;
import plus.extvos.auth.shiro.QuickToken;
import plus.extvos.auth.utils.CredentialGenerator;
import plus.extvos.auth.utils.CredentialHash;
import plus.extvos.common.Assert;
import plus.extvos.common.Result;
import plus.extvos.common.ResultCode;
import plus.extvos.common.Validator;
import plus.extvos.common.exception.ResultException;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.Base64;
import java.util.Map;

/**
 * @author Mingcai SHEN
 */
@Api(tags = {"用户认证"})
@RequestMapping("/auth")
@RestController
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private static final String CAPTCHA_SESSION_KEY = "CAPTCHA";
    private static final String VERIFIER_SESSION_KEY = "VERIFIER";
    private static final String FAILURE_SESSION_COUNT = "FAILURE_COUNT";

    @Autowired
    private Producer captchaProducer;

    @Autowired
    private QuickAuthService quickAuthService;

    @Autowired(required = false)
    private QuickAuthCallback quickAuthCallback;

    @Autowired(required = false)
    private UserRegisterHook userRegisterHook;

    @Autowired(required = false)
    private SMSService smsService;

    @Autowired
    private QuickAuthConfig authConfig;

    private LoginResult failureResult(int failures, String... errs) {
        LoginResult lr = new LoginResult();
        lr.setFailures(failures);
        if (errs.length > 0) {
            lr.setError(errs[0]);
        }
        return lr;
    }

    private boolean validateCaptcha(String captcha, ResultException... e) throws ResultException {
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        // Need to create session here, when it's first access.
        Session sess = sub.getSession(true);
        if (!captcha.equals(sess.getAttribute(CAPTCHA_SESSION_KEY))) {
            if (e.length > 0) {
                throw e[0];
            } else {
                return false;
            }
        }
        // Remove it for avoid second use.
        sess.removeAttribute(CAPTCHA_SESSION_KEY);
        return true;
    }

    private boolean validateVerifier(String verifier, ResultException... e) throws ResultException {
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        // Need to create session here, when it's first access.
        Session sess = sub.getSession(true);
        if (!verifier.equals(sess.getAttribute(VERIFIER_SESSION_KEY))) {
            if (e.length > 0) {
                throw e[0];
            } else {
                return false;
            }
        }
        // Remove it for avoid second use.
        sess.removeAttribute(VERIFIER_SESSION_KEY);
        return true;
    }

    @ApiOperation("登录账户")
    @PostMapping("/login")
    Result<LoginResult> doLogin(
            @RequestParam(value = "username", required = false) String username,
            @RequestParam(value = "email", required = false) String email,
            @RequestParam(value = "cellphone", required = false) String cellphone,
            @RequestParam(value = "verifier", required = false) String verifier,
            @RequestParam(value = "password", required = false) String password,
            @RequestParam(value = "salt", required = false) String salt,
            @RequestParam(value = "algorithm", required = false) String algorithm,
            @RequestParam(value = "captcha", required = false) String captcha,
            @RequestParam(value = "redirectUri", required = false) String redirectUri,
            @RequestBody(required = false) Map<String, String> params,
            HttpServletResponse response) throws ResultException {
        /* Support client to login with FORM or in JSON format */
        if (params != null && !params.isEmpty()) {
            username = params.getOrDefault("username", username);
            email = params.getOrDefault("email", email);
            cellphone = params.getOrDefault("cellphone", cellphone);
            verifier = params.getOrDefault("verifier", verifier);
            password = params.getOrDefault("password", password);
            salt = params.getOrDefault("salt", salt);
            algorithm = params.getOrDefault("algorithm", algorithm);
            captcha = params.getOrDefault("captcha", captcha);
            redirectUri = params.getOrDefault("redirectUri", redirectUri);
        }
        // Get subject and session
        Subject sub = SecurityUtils.getSubject();
        // Need to create session here, when it's first access.
        Session sess = sub.getSession(true);
        Integer fn = (Integer) sess.getAttribute(FAILURE_SESSION_COUNT);
        if (null == fn) {
            fn = 0;
        }
        boolean isCaptchaRequired = authConfig.isCaptchaRequired();
        log.info("doLogin:> failures: {}", fn);
        // If isAutoCaptcha and current session was failed more than once, we force to check captcha.
        // This is by session, we may need to support by source IP in the future.
        if (fn > 0 && authConfig.isAutoCaptcha()) {
            isCaptchaRequired = true;
        }
        UserInfo userInfo = null;
        String via = "";
        if (Validator.notEmpty(username)) {
            userInfo = quickAuthService.getUserByName(username, true);
            via = "username(" + username + ")";
        } else if (Validator.notEmpty(email)) {
            userInfo = quickAuthService.getUserByEmail(email, true);
            via = "email(" + email + ")";
        } else if (Validator.notEmpty(cellphone)) {
            userInfo = quickAuthService.getUserByPhone(cellphone, true);
            via = "cellphone(" + cellphone + ")";
        } else {
            throw ResultException.badRequest("username of email or cellphone required");
        }
        if (null == userInfo) {
            sess.setAttribute(FAILURE_SESSION_COUNT, fn + 1);
            throw ResultException.notFound(via + " not exists");
        }
        log.debug("Via " + via + " > " + userInfo.getUsername());
        username = userInfo.getUsername();
        // Performing sms login first
        if ((Validator.notEmpty(cellphone) || Validator.notEmpty(email)) && Validator.notEmpty(verifier)) {
//            String smsText = sess.getAttribute(VERIFIER_SESSION_KEY).toString();
            if (!verifier.equals(sess.getAttribute(VERIFIER_SESSION_KEY))) {
                log.error("doLogin:> [{}:{}] 验证码错误", cellphone, email);
                throw new ResultException(AuthCode.INCORRECT_VERIFIER, "验证码错误", failureResult(fn + 1));
            } else {
                password = userInfo.getPassword();
            }
            // Remove it for avoid second use.
            sess.removeAttribute(VERIFIER_SESSION_KEY);
        } else {
            try {
//                Assert.notEmpty(username, new ResultException(AuthCode.USERNAME_REQUIRED, "Username required!", failureResult(fn + 1)));
                Assert.notEmpty(password, new ResultException(AuthCode.PASSWORD_REQUIRED, "Password required!", failureResult(fn + 1)));
                log.info("/auth/login: [{},{},{}]", username, password, redirectUri);
                if (authConfig.isSaltRequired()) {
                    Assert.notEmpty(salt, new ResultException(AuthCode.SALT_REQUIRED, "Salt required!", failureResult(fn + 1)));
                }
                if (isCaptchaRequired) {
                    Assert.notEmpty(captcha, new ResultException(AuthCode.CAPTCHA_REQUIRED, "Captcha required!", failureResult(fn + 1)));
                }
            } catch (ResultException e) {
                sess.setAttribute(FAILURE_SESSION_COUNT, fn + 1);
                throw e;
            }

            if (captcha != null && !captcha.isEmpty()) {
//                String capText = null != sess.getAttribute(CAPTCHA_SESSION_KEY) ? sess.getAttribute(CAPTCHA_SESSION_KEY).toString() : "";
                if (!captcha.equals(sess.getAttribute(CAPTCHA_SESSION_KEY))) {
                    log.error("doLogin:> [{}] 验证码错误", username);
                    sess.setAttribute(FAILURE_SESSION_COUNT, fn + 1);
                    throw new ResultException(AuthCode.INCORRECT_CAPTCHA, "验证码错误", failureResult(fn + 1));
                }
                // Remove it for avoid second use.
                sess.removeAttribute(CAPTCHA_SESSION_KEY);
            }
        }
        // Perform the login
        QuickToken token = new QuickToken(username, password, algorithm, salt);
        try {
            sub.login(token);
            userInfo = quickAuthService.fillUserInfo(userInfo);
            if (null != quickAuthCallback) {
                userInfo = quickAuthCallback.onLoggedIn(userInfo);
            }
            sess.setAttribute(UserInfo.USER_INFO_KEY, userInfo);
            if (redirectUri != null && !redirectUri.isEmpty()) {
                redirectUri += "?code=" + sess.getId();
                response.sendRedirect(redirectUri);
                return null;
            } else {
                userInfo.setPassword("*******");
                LoginResult lr = new LoginResult(token.getUsername(), sess.getId(), null, null, userInfo);
                if (StringUtils.hasLength(redirectUri)) {
                    lr.setRedirectUri(redirectUri);
                    lr.setRedirect(true);
                } else {
                    lr.setRedirect(false);
                }
                sess.removeAttribute(FAILURE_SESSION_COUNT);
                return Result.data(lr).success();
            }
        } catch (UnknownAccountException e) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,用户不存在", username);
            token.clear();
            sess.setAttribute(FAILURE_SESSION_COUNT, fn + 1);
//            return Result.data(failureResult(fn + 1)).setMsg("").failure();
            return Result.data(failureResult(fn + 1)).setMsg("用户不存在").failure(AuthCode.ACCOUNT_NOT_FOUND);
        } catch (LockedAccountException lae) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,账户已锁定", username);
            token.clear();
            sess.setAttribute(FAILURE_SESSION_COUNT, fn + 1);
            return Result.data(failureResult(fn + 1)).setMsg("账户已锁定").failure(AuthCode.ACCOUNT_LOCKED);
        } catch (DisabledAccountException lae) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,账户未启用", username);
            token.clear();
            sess.setAttribute(FAILURE_SESSION_COUNT, fn + 1);
            return Result.data(failureResult(fn + 1)).setMsg("账户未启用").failure(AuthCode.ACCOUNT_DISABLED);
        } catch (ExcessiveAttemptsException e) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,错误次数过多", username);
            token.clear();
            sess.setAttribute(FAILURE_SESSION_COUNT, fn + 1);
            return Result.data(failureResult(fn + 1)).setMsg("错误次数过").failure(AuthCode.TOO_MAY_RETRIES);
        } catch (CredentialsException e) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,密码或用户名错误", username);
            token.clear();
            sess.setAttribute(FAILURE_SESSION_COUNT, fn + 1);
            return Result.data(failureResult(fn + 1)).setMsg("密码或用户名错误").failure(AuthCode.INCORRECT_CREDENTIALS);
        } catch (AuthenticationException e) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,堆栈轨迹如下", username, e);
            token.clear();
            sess.setAttribute(FAILURE_SESSION_COUNT, fn + 1);
            return Result.data(failureResult(fn + 1)).setMsg("密码或用户名错误").failure(AuthCode.INCORRECT_CREDENTIALS);
        } catch (Exception e) {
            sess.setAttribute(FAILURE_SESSION_COUNT, fn + 1);
            return Result.data(failureResult(fn + 1)).setMsg(e.getMessage()).failure(ResultCode.INTERNAL_SERVER_ERROR);
//            return Result.message(e.getMessage()).with(failureResult(fn + 1)).failure(ResultCode.INTERNAL_SERVER_ERROR);
        }
    }

    @ApiOperation(value = "退出登录", notes = "该接口永远返回正确值，默认情况下我们无需理会")
    @PostMapping("/logout")
    public Result<String> doLogout(@SessionUser UserInfo userInfo) throws ResultException {
        try {
            Subject subject = SecurityUtils.getSubject();
            log.debug("doLogout:> {} logout ...", subject.getPrincipal());
            subject.logout();
            if (null != quickAuthCallback) {
                quickAuthCallback.onLogout(userInfo);
            }
        } catch (Exception e) {
            log.warn("doLogout:> failed: ", e);
        }

        return Result.data("DONE").success();
    }

    private Base64.Encoder getB64Encoder() {
        return Base64.getEncoder();
    }


    @ApiOperation(value = "获取图片验证码", notes = "获取以JSON格式包含的图片验证码")
    @RequestMapping(value = "/captcha", method = RequestMethod.GET)
    @ResponseBody
    protected Result<String> getCaptchaImageInText(@RequestParam(required = false) Map<String, Object> ignoredQueries)
            throws IOException {
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession(true);
        // 生成验证码文本
        String capText = captchaProducer.createText();
        session.setAttribute(CAPTCHA_SESSION_KEY, capText);
        log.debug("generateCaptchaImage:> capText = {}", capText);
        // 利用生成的字符串构建图片
        BufferedImage bi = captchaProducer.createImage(capText);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(bi, "png", baos);
        byte[] bytes = baos.toByteArray();
        String imageData = "data:image/png;base64," + getB64Encoder().encodeToString(bytes).replace("\r\n", "").replace("\n", "");
        return Result.data(imageData).success();
    }

    @ApiOperation(value = "获取图片验证码", notes = "获取图片验证码，直接输出图片")
    @RequestMapping(produces = MediaType.IMAGE_PNG_VALUE, value = "/captcha-image", method = RequestMethod.GET)
    protected ModelAndView getCaptchaImageRaw(final HttpServletRequest request, HttpServletResponse response) throws IOException {

        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession(true);

        response.setDateHeader("Expires", 0);
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        response.addHeader("Cache-Control", "post-check=0, pre-check=0");
        response.setHeader("Pragma", "no-cache");
        response.setContentType("image/png");

        // 生成验证码文本
        long start = System.currentTimeMillis();
        String capText = captchaProducer.createText();
        log.debug(capText);
        session.setAttribute(CAPTCHA_SESSION_KEY, capText);
        // 利用生成的字符串构建图片
        BufferedImage bi = captchaProducer.createImage(capText);
        ServletOutputStream out = response.getOutputStream();
        ImageIO.write(bi, "png", out);
        try {
            out.flush();
        } finally {
            out.close();
        }
        return null;
    }

    @ApiOperation(value = "校验验证码", notes = "校验当前session获取的验证码是否正确")
    @PostMapping("/validate-captcha")
    public Result<String> validateCaptchaRequest(@RequestParam(value = "captcha") String captcha) {
        if (null == captcha || captcha.isEmpty()) {
            throw ResultException.badRequest("captcha required");
        }
        Subject sub = SecurityUtils.getSubject();
        Session sess = sub.getSession();
        if (null == sess) {
            throw ResultException.badRequest("session not exists");
        }
        if (!captcha.equals(sess.getAttribute(CAPTCHA_SESSION_KEY))) {
            log.error("performSMSCode:> [{}] 验证码错误", captcha);
            throw new ResultException(AuthCode.INCORRECT_CAPTCHA, "验证码错误");
        }
        // Remove it for avoid second use.
        sess.removeAttribute(CAPTCHA_SESSION_KEY);
        return Result.data("OK").success();
    }

    @ApiOperation(value = "发送手机验证码", notes = "根据用户手机号发送随机验证码，用于后续登录")
    @PostMapping("/send-smscode")
    public Result<String> performSMSCode(@RequestParam(value = "cellphone", required = false) String cellphone,
                                         @RequestParam(value = "captcha", required = false) String captcha,
                                         @RequestBody(required = false) Map<String, String> params) {
        if (null == smsService) {
            throw ResultException.notImplemented("SMS service is unavailable.");
        }
        if (Validator.notEmpty(params)) {
            cellphone = params.getOrDefault("cellphone", "");
            captcha = params.getOrDefault("captcha", "");
        }

        Assert.notEmpty(cellphone, new ResultException(AuthCode.CELLPHONE_REQUIRED, "Cellphone required!"));

        if (authConfig.isCaptchaRequired()) {
            Assert.notEmpty(captcha, new ResultException(AuthCode.CAPTCHA_REQUIRED, "Captcha required!"));
        }
        Subject sub = SecurityUtils.getSubject();
        Session sess = sub.getSession();
        if (captcha != null && !captcha.isEmpty()) {
            if (!captcha.equals(sess.getAttribute(CAPTCHA_SESSION_KEY))) {
                log.error("performSMSCode:> [{}] 验证码错误", cellphone);
                throw new ResultException(AuthCode.INCORRECT_CAPTCHA, "验证码错误");
            }
            // Remove it for avoid second use.
            sess.removeAttribute(CAPTCHA_SESSION_KEY);
        }
        String code = CredentialGenerator.getDecimalDigits(authConfig.getSmsCodeLength());
        sess.setAttribute(VERIFIER_SESSION_KEY, code);
        if (smsService.sendSecretCode(cellphone, code)) {
            return Result.data("OK").success();
        } else {
            throw ResultException.serviceUnavailable("send sms code failed.");
        }
    }

    @ApiOperation(value = "校验手机验证码", notes = "校验当前发送的验证码")
    @PostMapping("/validate-smscode")
    public Result<?> validateSMSCodeRequest(@RequestParam(value = "code") String code) {
        if (null == code || code.isEmpty()) {
            throw ResultException.badRequest("code required");
        }
        Subject sub = SecurityUtils.getSubject();
        Session sess = sub.getSession();
        if (null == sess) {
            throw ResultException.badRequest("session not exists");
        }
        if (!code.equals(sess.getAttribute(VERIFIER_SESSION_KEY))) {
            log.error("validateSMSCode:> [{}] 验证码错误", code);
            throw new ResultException(AuthCode.INCORRECT_VERIFIER, "验证码错误");
        }
        // Remove it for avoid second use.
        sess.removeAttribute(VERIFIER_SESSION_KEY);
        return Result.data("OK").success();
    }

    @ApiOperation(value = "用户注册", notes = "注册一个新用户接口")
    @PostMapping("/register")
    public Result<UserInfo> registerUser(
            @RequestParam(value = "username", required = false) String username,
            @RequestParam(value = "password", required = false) String password,
            @RequestParam(value = "captcha", required = false) String captcha,
            @RequestParam(value = "verifier", required = false) String verifier,
            @RequestBody(required = false) Map<String, Object> params) throws ResultException {
        Assert.isTrue(authConfig.isRegisterAllowed(), ResultException.forbidden("self register is not allowed"));
//        Assert.notEmpty(params, ResultException.forbidden("invalid empty request body"));
        if (authConfig.isRegisterCaptchaRequired()) {
            Assert.notEmpty(captcha, new ResultException(AuthCode.CAPTCHA_REQUIRED, "Captcha required!"));
            validateCaptcha(captcha, new ResultException(AuthCode.INCORRECT_CAPTCHA, "Incorrect captcha"));
        }
        if (authConfig.isRegisterVerifierRequired()) {
            Assert.notEmpty(verifier, new ResultException(AuthCode.VERIFIER_REQUIRED, "Verifier required!"));
            validateVerifier(verifier, new ResultException(AuthCode.INCORRECT_VERIFIER, "Incorrect verifier"));
        }
        String[] perms = null;
        String[] roles = null;
        short status = 0;
        if (Validator.notEmpty(params)) {
            username = params.getOrDefault("username", username).toString();
            password = params.getOrDefault("password", password).toString();
            params.remove("username");
            params.remove("password");
        }
        Assert.notEmpty(username, ResultException.forbidden("invalid empty username"));
        Assert.notEmpty(password, ResultException.forbidden("invalid empty password"));
        if (userRegisterHook != null) {
            if (!userRegisterHook.preRegister(username, password, params, UserRegisterHook.OPEN)) {
                throw ResultException.forbidden("not allowed to register user");
            }
            perms = userRegisterHook.defaultPermissions(UserRegisterHook.OPEN);
            roles = userRegisterHook.defaultRoles(UserRegisterHook.OPEN);
            status = userRegisterHook.defaultStatus(UserRegisterHook.OPEN);
        }
        UserInfo u = quickAuthService.getUserByName(username, false);
        if (u != null) {
            throw ResultException.conflict("user with username '" + username + "' already exists");
        }

        Serializable userId = quickAuthService.createUserInfo(username, password, status, perms, roles, params);
        Assert.notNull(userId, ResultException.serviceUnavailable("create user failed"));
        UserInfo userInfo = new UserInfo(userId, username, "", "", "");
        if (Validator.notEmpty(params)) {
            if (params.containsKey("email")) {
                userInfo.setEmail(params.get("email").toString());
            }
            if (params.containsKey("cellphone")) {
                userInfo.setCellphone(params.get("cellphone").toString());
            }
        }
        return Result.data(userInfo).success();
    }

    @ApiOperation(value = "重置密码", notes = "重置用户密码")
    @PostMapping("/reset-password")
    @RequiresAuthentication
    public Result<String> resetPassword(@RequestParam(value = "verifier", required = true) String verifier,
                                        @RequestParam(value = "newPassword1", required = false) String newPassword1,
                                        @RequestParam(value = "newPassword2", required = false) String newPassword2,
                                        @RequestBody(required = false) Map<String, String> params,
                                        @SessionUser String username) throws ResultException {
        if (Validator.notEmpty(params)) {
            verifier = params.getOrDefault("verifier", "");
            newPassword1 = params.getOrDefault("newPassword1", "");
            newPassword2 = params.getOrDefault("newPassword2", "");
        }
        Assert.notEmpty(username, ResultException.forbidden("can not get current username"));
        Assert.notEmpty(verifier, ResultException.badRequest("verifier can not be empty"));
        Assert.notEmpty(newPassword1, ResultException.badRequest("newPassword1 can not be empty"));
        Assert.notEmpty(newPassword2, ResultException.badRequest("newPassword2 can not be empty"));
        Assert.equals(newPassword1, newPassword2, ResultException.badRequest("newPassword1 and newPassword2 should be the same"));
        UserInfo userInfo = quickAuthService.getUserByName(username, false);
        if (null == userInfo) {
            throw ResultException.forbidden("can not get userInfo");
        }
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession(false);
        if (null == session) {
            throw ResultException.forbidden("not in a session");
        }
        Assert.equals(verifier, session.getAttribute(VERIFIER_SESSION_KEY), ResultException.forbidden("invalid verifier"));
        quickAuthService.updateUserInfo(username, newPassword1, null, null, null);
        return Result.data("OK").success();
    }

    @ApiOperation(value = "更改密码", notes = "更改用户密码")
    @PostMapping("/change-password")
    @RequiresAuthentication
    public Result<String> changePassword(@RequestParam(value = "oldPassword", required = false) String oldPassword,
                                         @RequestParam(value = "newPassword1", required = false) String newPassword1,
                                         @RequestParam(value = "newPassword2", required = false) String newPassword2,
                                         @RequestParam(value = "salt", required = false) String salt,
                                         @RequestParam(value = "algorithm", required = false) String algorithm,
                                         @RequestBody(required = false) Map<String, String> params,
                                         @SessionUser String username) throws ResultException {
        if (Validator.notEmpty(params)) {
            oldPassword = params.getOrDefault("oldPassword", "");
            newPassword1 = params.getOrDefault("newPassword1", "");
            newPassword2 = params.getOrDefault("newPassword2", "");
            salt = params.getOrDefault("salt", "");
            algorithm = params.getOrDefault("algorithm", "");
        }
        Assert.notEmpty(username, ResultException.forbidden("can not get current username"));
        Assert.notEmpty(oldPassword, ResultException.badRequest("oldPassword can not be empty"));
        Assert.notEmpty(newPassword1, ResultException.badRequest("newPassword1 can not be empty"));
        Assert.notEmpty(newPassword2, ResultException.badRequest("newPassword2 can not be empty"));
        Assert.equals(newPassword1, newPassword2, ResultException.badRequest("newPassword1 and newPassword2 should be the same"));
        UserInfo userInfo = quickAuthService.getUserByName(username, false);
        if (salt != null && !salt.isEmpty()) {
            algorithm = algorithm == null || algorithm.isEmpty() ? "MD5" : algorithm;
            try {
                if (CredentialHash.algorithm(algorithm).salt(salt).password(userInfo.getPassword()).encrypt().equals(oldPassword)) {
                    throw ResultException.forbidden("incorrect old password");
                }
            } catch (Exception e) {
                log.warn(">>", e);
                throw ResultException.badRequest("invalid algorithm or ...");
            }
        } else if (!oldPassword.equals(userInfo.getPassword())) {
            throw ResultException.forbidden("incorrect old password");
        }
        quickAuthService.updateUserInfo(username, newPassword1, null, null, null);
        return Result.data("OK").success();
    }

    @ApiOperation(value = "用户信息", notes = "获取当前会话用户信息")
    @GetMapping("/profile")
    @RequiresAuthentication
    public Result<UserInfo> getUserProfile(@SessionUser UserInfo userInfo) throws ResultException {
        Assert.notNull(userInfo, ResultException.forbidden("can not get current userInfo"));
        userInfo.setPassword("******");
        return Result.data(userInfo).success();
    }

    @PostMapping("/check-username")
    @ApiOperation(value = "检查户名", notes = "按用户名检查户名是否已注册")
    public Result<CheckResult> checkUsername(@RequestParam("username") String username) throws ResultException {
        UserInfo m = quickAuthService.getUserByName(username, false);
        if (null != m) {
            return Result.data(new CheckResult("username", true)).success();
        } else {
            return Result.data(new CheckResult("username", false)).success();
        }
    }

    @PostMapping("/check-email")
    @ApiOperation(value = "检查户名", notes = "按邮件检查户名是否已注册")
    public Result<CheckResult> checkEmail(@RequestParam("email") String email) throws ResultException {
        UserInfo m = quickAuthService.getUserByEmail(email, false);
        if (null != m) {
            return Result.data(new CheckResult("email", true)).success();
        } else {
            return Result.data(new CheckResult("email", false)).success();
        }
    }

    @PostMapping("/check-cellphone")
    @ApiOperation(value = "检查户名", notes = "按电话检查户名是否已注册")
    public Result<CheckResult> checkCellphone(@RequestParam("cellphone") String cellphone) throws ResultException {
        UserInfo m = quickAuthService.getUserByPhone(cellphone, false);
        if (null != m) {
            return Result.data(new CheckResult("cellphone", true)).success();
        } else {
            return Result.data(new CheckResult("cellphone", false)).success();
        }
    }
}
