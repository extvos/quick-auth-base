package org.extvos.auth.enums;

import org.extvos.restlet.Code;

/**
 * @author shenmc
 */

public enum AuthCode implements Code {
    /**
     *
     */
    CAPTCHA_REQUIRED(40001,"验证码未提供 "),
    INCORRECT_CAPTCHA(40002,"验证码无效 "),
    SALT_REQUIRED(40003,"未提供加扰盐 "),

    /**
     *
     */
    ACCOUNT_DISABLED(40301, "Account Disabled"),
    ACCOUNT_LOCKED(40302, "Account Locked"),
    TOO_MAY_RETRIES(40303,"Too Many Retries"),
    INCORRECT_CREDENTIALS(40304,"Incorrect Credentials"),
    /**
     *
     */
    ACCOUNT_NOT_FOUND(40401,"Account Not Found")
    ;

    private final int value;
    private final String desc;

    AuthCode(int v, String d) {
        value = v;
        desc = d;
    }


    @Override
    public int value() {
        return this.value;
    }

    @Override
    public int status() {
        return this.value / 100;
    }

    @Override
    public String desc() {
        return this.desc;
    }
}
