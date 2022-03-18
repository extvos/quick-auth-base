package plus.extvos.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.io.Serializable;

public class LoginResult {
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String username;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Serializable code;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String redirectUri;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Boolean redirect;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private UserInfo userInfo;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer failures;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String error;

    public LoginResult() {
    }

    public LoginResult(String username, Serializable code, String redirectUri, Boolean redirect, UserInfo userInfo) {
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
}
