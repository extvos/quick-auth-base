package org.extvos.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

/**
 * @author Mingcai SHEN
 */
@Configuration
@ConfigurationProperties(prefix = "quick.auth.base")
public class QuickAuthConfig {
    private String secret = "quick";
    private boolean saltRequired = false;
    private boolean captchaRequired = false;
    private boolean registerAllowed = false;
    private boolean phoneRequired = false;
    private int smsCodeLength = 6;

    public String getSecret() {
        return secret;
    }

    public boolean isSaltRequired() {
        return saltRequired;
    }

    public boolean isCaptchaRequired() {
        return captchaRequired;
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
}
