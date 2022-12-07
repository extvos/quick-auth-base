package plus.extvos.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * @author Mingcai SHEN
 */
@Configuration
@ConfigurationProperties(prefix = "quick.auth.base")
public class QuickAuthConfig {
    private String secret = "quick";
    private int maxAge = 2592000;
    private boolean saltRequired = false;
    private boolean captchaRequired = false;
    private boolean autoCaptcha = false;
    private boolean registerAllowed = false;
    private boolean registerCaptchaRequired = true;
    private boolean registerVerifierRequired = false;
    private boolean phoneRequired = false;
    private int smsCodeLength = 6;

    private short defaultStatus = 0;

    private String defaultRoles = "";

    private String defaultPermissions = "";
    private String siteName = "QuickStart";

    private String logoImage = "";

    public String getSecret() {
        return secret;
    }

    public byte[] getSecretAsCypher() {
        byte[] bs = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        byte[] ss = secret.getBytes();
        System.arraycopy(ss, 0, bs, 0, Math.min(ss.length, 16));
        return bs;
    }

    public int getMaxAge() {
        return maxAge;
    }

    public void setMaxAge(int maxAge) {
        this.maxAge = maxAge;
    }

    public boolean isSaltRequired() {
        return saltRequired;
    }

    public boolean isCaptchaRequired() {
        return captchaRequired;
    }

    public boolean isAutoCaptcha() {
        return autoCaptcha;
    }

    public void setAutoCaptcha(boolean autoCaptcha) {
        this.autoCaptcha = autoCaptcha;
    }

    public boolean isRegisterAllowed() {
        return registerAllowed;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public void setSaltRequired(boolean saltRequired) {
        this.saltRequired = saltRequired;
    }

    public void setCaptchaRequired(boolean captchaRequired) {
        this.captchaRequired = captchaRequired;
    }

    public void setRegisterAllowed(boolean registerAllowed) {
        this.registerAllowed = registerAllowed;
    }

    public boolean isPhoneRequired() {
        return phoneRequired;
    }

    public void setPhoneRequired(boolean phoneRequired) {
        this.phoneRequired = phoneRequired;
    }

    public int getSmsCodeLength() {
        return smsCodeLength;
    }

    public void setSmsCodeLength(int smsCodeLength) {
        this.smsCodeLength = smsCodeLength;
    }

    public boolean isRegisterCaptchaRequired() {
        return registerCaptchaRequired;
    }

    public void setRegisterCaptchaRequired(boolean registerCaptchaRequired) {
        this.registerCaptchaRequired = registerCaptchaRequired;
    }

    public boolean isRegisterVerifierRequired() {
        return registerVerifierRequired;
    }

    public void setRegisterVerifierRequired(boolean registerVerifierRequired) {
        this.registerVerifierRequired = registerVerifierRequired;
    }

    public short getDefaultStatus() {
        return defaultStatus;
    }

    public void setDefaultStatus(short defaultStatus) {
        this.defaultStatus = defaultStatus;
    }

    public String getDefaultRoles() {
        return defaultRoles;
    }

    public void setDefaultRoles(String defaultRoles) {
        this.defaultRoles = defaultRoles;
    }

    public String getDefaultPermissions() {
        return defaultPermissions;
    }

    public void setDefaultPermissions(String defaultPermissions) {
        this.defaultPermissions = defaultPermissions;
    }

    public String getSiteName() {
        return siteName;
    }

    public void setSiteName(String siteName) {
        this.siteName = siteName;
    }

    public String getLogoImage() {
        return logoImage;
    }

    public void setLogoImage(String logoImage) {
        this.logoImage = logoImage;
    }
}
