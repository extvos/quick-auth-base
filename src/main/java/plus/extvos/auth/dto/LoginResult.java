package plus.extvos.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import plus.extvos.common.Code;
import plus.extvos.common.ResultCode;

import java.io.Serializable;

public class LoginResult implements Serializable {
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String username;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Serializable code;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String redirectUri;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Boolean redirect;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Boolean remembered;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private UserInfo userInfo;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer failures;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String error;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Code result;

    public LoginResult() {
        this.result = ResultCode.OK;
    }

    public LoginResult(Code ret, int failures, String err) {
        this.result = ret;
        this.failures = failures;
        this.error = err;
    }

    public LoginResult(String username, Serializable code, String redirectUri, Boolean redirect, UserInfo userInfo) {
        this.result = ResultCode.OK;
        this.username = username;
        this.code = code;
        this.redirectUri = redirectUri;
        this.redirect = redirect;
        this.userInfo = userInfo;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Serializable getCode() {
        return code;
    }

    public void setCode(Serializable code) {
        this.code = code;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public Boolean getRedirect() {
        return redirect;
    }

    public void setRedirect(Boolean redirect) {
        this.redirect = redirect;
    }

    public UserInfo getUserInfo() {
        return userInfo;
    }

    public void setUserInfo(UserInfo userInfo) {
        this.userInfo = userInfo;
    }

    public Integer getFailures() {
        return failures;
    }

    public void setFailures(Integer failures) {
        this.failures = failures;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public Boolean getRemembered() {
        return remembered;
    }

    public void setRemembered(Boolean remembered) {
        this.remembered = remembered;
    }

    public Code getResult() {
        return result;
    }

    public void setResult(Code result) {
        this.result = result;
    }
}
