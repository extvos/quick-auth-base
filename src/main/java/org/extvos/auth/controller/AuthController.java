package org.extvos.auth.controller;

import com.google.code.kaptcha.Producer;
import org.extvos.auth.annotation.SessionUser;
import org.extvos.auth.config.QuickAuthConfig;
import org.extvos.auth.dto.PermissionInfo;
import org.extvos.auth.dto.RoleInfo;
import org.extvos.auth.dto.UserInfo;
import org.extvos.auth.enums.AuthCode;
import org.extvos.auth.service.QuickAuthService;
import org.extvos.auth.shiro.QuickToken;
import org.extvos.auth.utils.CredentialHash;
import org.extvos.restlet.Assert;
import org.extvos.restlet.RestletCode;
import org.extvos.restlet.Result;
import org.extvos.restlet.exception.RestletException;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.*;

/**
 * @author Mingcai SHEN
 */
@Api(tags = {"用户认证"})
@RequestMapping("/auth")
@RestController
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private static final String CAPTCHA_SESSION_KEY = "CAPTCHA";

    @Autowired
    private Producer captchaProducer;

    @Autowired
    private QuickAuthService quickAuthService;

    @Autowired
    private QuickAuthConfig authConfig;

    @ApiOperation("登录账户")
    @PostMapping("/login")
    Result<?> doLogin(
            @RequestParam("username") String username,
            @RequestParam("password") String password,
            @RequestParam(value = "salt", required = false) String salt,
            @RequestParam(value = "algorithm", required = false) String algorithm,
            @RequestParam(value = "captcha", required = false) String captcha,
            @RequestParam(value = "redirectUri", required = false) String redirectUri,
            @RequestBody(required = false) Map<String, String> params,
            HttpServletResponse response) throws RestletException {
        if (params != null && !params.isEmpty()) {
            username = params.getOrDefault("username", username);
            password = params.getOrDefault("password", password);
            salt = params.getOrDefault("salt", salt);
            algorithm = params.getOrDefault("algorithm", algorithm);
            captcha = params.getOrDefault("captcha", captcha);
            redirectUri = params.getOrDefault("redirectUri", redirectUri);
        }
        log.info("/auth/login: [{},{},{}]", username, password, redirectUri);
        if (authConfig.isSaltRequired()) {
            Assert.notEmpty(salt, new RestletException(AuthCode.SALT_REQUIRED, "Salt required!"));
        }
        if (authConfig.isCaptchaRequired()) {
            Assert.notEmpty(captcha, new RestletException(AuthCode.CAPTCHA_REQUIRED, "Captcha required!"));
        }
        // 想要得到 SecurityUtils.getSubject() 的对象．．访问地址必须跟 shiro 的拦截地址内．不然后会报空指针
        Subject sub = SecurityUtils.getSubject();
        Session sess = sub.getSession();

        if (captcha != null && !captcha.isEmpty()) {
            String capText = sess.getAttribute(CAPTCHA_SESSION_KEY).toString();
            if (!captcha.equals(capText)) {
                log.error("doLogin:> [{}] 验证码错误", username);
                throw new RestletException(AuthCode.INCORRECT_CAPTCHA, "验证码错误");
            }
            // Remove it for avoid second use.
            sess.removeAttribute(CAPTCHA_SESSION_KEY);
        }
        // 用户输入的账号和密码,,存到UsernamePasswordToken对象中..然后由shiro内部认证对比,
        // 认证执行者交由 org.extvos.auth.shiro.QuickRealm 中 doGetAuthenticationInfo 处理
        // 当以上认证成功后会向下执行,认证失败会抛出异常
        QuickToken token = new QuickToken(username, password, algorithm, salt);
        Result<?> result;
        try {
            sub.login(token);
            if (redirectUri != null && !redirectUri.isEmpty()) {
                redirectUri += "?code=" + sess.getId();
                response.sendRedirect(redirectUri);
                return null;
            } else {
                Map<String, Object> prof = new HashMap<>(5);
                prof.put("username", token.getUsername());
                if (StringUtils.hasLength(redirectUri)) {
                    prof.put("redirectUri", redirectUri);
                    prof.put("code", sess.getId());
                    prof.put("redirect", true);
                } else {
                    prof.put("redirect", false);
                }
                return Result.data(prof).success();
            }
        } catch (UnknownAccountException e) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,用户不存在", username);
            token.clear();
            return Result.message("用户不存在").failure(AuthCode.ACCOUNT_NOT_FOUND);
        } catch (LockedAccountException lae) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,账户已锁定", username);
            token.clear();
            return Result.message("账户已锁定").failure(AuthCode.ACCOUNT_LOCKED);
        } catch (DisabledAccountException lae) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,账户未启用", username);
            token.clear();
            return Result.message("账户未启用").failure(AuthCode.ACCOUNT_DISABLED);
        } catch (ExcessiveAttemptsException e) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,错误次数过多", username);
            token.clear();
            return Result.message("错误次数过").failure(AuthCode.TOO_MAY_RETRIES);
        } catch (CredentialsException e) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,密码或用户名错误", username);
            token.clear();
            return Result.message("密码或用户名错误").failure(AuthCode.INCORRECT_CREDENTIALS);
        } catch (AuthenticationException e) {
            log.error("doLogin:> 对用户[{}]进行登录验证,验证未通过,堆栈轨迹如下", username, e);
            token.clear();
            return Result.message("密码或用户名错误").failure(AuthCode.INCORRECT_CREDENTIALS);
        } catch (Exception e) {
            return Result.message(e.getMessage()).failure(RestletCode.INTERNAL_SERVER_ERROR);
        }
    }

    @ApiOperation(value = "退出登录", notes = "该接口永远返回正确值，默认情况下我们无需理会")
    @PostMapping("/logout")
    public Result<?> doLogout() throws RestletException {
        try {
            Subject subject = SecurityUtils.getSubject();
            log.debug("doLogout:> {} logout ...", subject.getPrincipal());
            subject.logout();
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
    protected Result<String> getCaptchaImageInText()
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

    @ApiOperation(value = "获取图片验证码", notes = "获取图片验证码，直接输出图片", position = 3)
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

    @ApiOperation(value = "用户注册", notes = "注册一个新用户接口")
    @PostMapping("/register")
    public Result<?> registerUser(@RequestBody Map<String, Object> params) throws RestletException {
        Assert.isTrue(authConfig.isRegisterAllowed(), RestletException.forbidden("self register is not allowed"));
        Assert.notEmpty(params, RestletException.forbidden("invalid empty request body"));
        String username = params.get("username").toString();
        String password = params.get("password").toString();
        String[] perms = null;
        String[] roles = null;
        Object pms = params.get("permissions");
        if (pms instanceof String[]) {
            perms = (String[]) pms;
        }
        Object rs = params.get("roles");
        if (rs instanceof String[]) {
            roles = (String[]) rs;
        }
        Assert.notEmpty(username, RestletException.forbidden("invalid empty username"));
        Assert.notEmpty(password, RestletException.forbidden("invalid empty password"));
        params.remove("username");
        params.remove("password");
        UserInfo u = quickAuthService.getUserByName(username, false);
        if (u != null) {
            throw RestletException.conflict("user with username '" + username + "' already exists");
        }
        Serializable userId = quickAuthService.createUserInfo(username, password, perms, roles, params);
        Assert.notNull(userId, RestletException.serviceUnavailable("create user failed"));
        Map<String, Object> ret = new LinkedHashMap<>();
        ret.put("username", username);
        ret.put("userId", userId);
        return Result.data(ret).success();
    }

    @ApiOperation(value = "更改密码", notes = "更改用户密码")
    @PostMapping("/change-password")
    @RequiresAuthentication
    public Result<?> changePassword(@RequestParam("oldPassword") String oldPassword,
                                    @RequestParam("newPassword1") String newPassword1,
                                    @RequestParam("newPassword2") String newPassword2,
                                    @RequestParam(value = "salt", required = false) String salt,
                                    @RequestParam(value = "algorithm", required = false) String algorithm,
                                    @SessionUser String username) throws RestletException {
        Assert.notEmpty(username, RestletException.forbidden("can not get current username"));
        Assert.notEmpty(oldPassword, RestletException.badRequest("oldPassword can not be empty"));
        Assert.notEmpty(newPassword1, RestletException.badRequest("newPassword1 can not be empty"));
        Assert.notEmpty(newPassword2, RestletException.badRequest("newPassword2 can not be empty"));
        Assert.equals(newPassword1, newPassword2, RestletException.badRequest("newPassword1 and newPassword2 should be the same"));
        UserInfo userInfo = quickAuthService.getUserByName(username, false);
        if (salt != null && !salt.isEmpty()) {
            algorithm = algorithm == null || algorithm.isEmpty() ? "MD5" : algorithm;
            try {
                if (CredentialHash.algorithm(algorithm).salt(salt).password(userInfo.getPassword()).encrypt().equals(oldPassword)) {
                    throw RestletException.forbidden("incorrect old password");
                }
            } catch (Exception e) {
                log.warn(">>", e);
                throw RestletException.badRequest("invalid algorithm or ...");
            }
        } else if (!oldPassword.equals(userInfo.getPassword())) {
            throw RestletException.forbidden("incorrect old password");
        }
        quickAuthService.updateUserInfo(username, newPassword1, null, null, null);
        return Result.data("OK").success();
    }

    @ApiOperation(value = "用户信息", notes = "获取当前会话用户信息")
    @GetMapping("/profile")
    @RequiresAuthentication
    public Result<UserInfo> getUserProfile(@SessionUser String username) throws RestletException {
        Assert.notEmpty(username, RestletException.forbidden("can not get current username"));
        UserInfo userInfo = quickAuthService.getUserByName(username, false);
        List<RoleInfo> roles = quickAuthService.getRoles(userInfo.getId());
        List<String> roleCodes = new LinkedList<>();
        roles.forEach(role -> {
            roleCodes.add(role.getCode());
        });
        List<PermissionInfo> perms = quickAuthService.getPermissions(userInfo.getId());
        List<String> permCodes = new LinkedList<>();
        perms.forEach(role -> {
            permCodes.add(role.getCode());
        });
        userInfo.setRoles(roleCodes.toArray(new String[0]));
        userInfo.setPermissions(permCodes.toArray(new String[0]));
        userInfo.setPassword("******");

        return Result.data(userInfo).success();
    }
}
