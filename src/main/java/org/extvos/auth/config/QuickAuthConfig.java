package org.extvos.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * @author Mingcai SHEN
 */
@Component
@ConfigurationProperties(prefix = "quick.auth.base")
public class QuickAuthConfig {
    private String secret = "quick";
    private boolean saltRequired = false;
    private boolean captchaRequired = false;
    private boolean registerAllowed = false;

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
}
