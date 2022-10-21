package plus.extvos.auth.dto;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Map;

/**
 * UserInfo presented information of logged in user with basic properties and
 * connected open account properties if current session is logged via open account.
 *
 * @author Mingcai SHEN
 */
public class UserInfo implements Serializable {

    public static final String USER_INFO_KEY = "QUICK_USER_INFO";
    /**
     * User Id
     */
    private Serializable userId;

    /**
     * Username
     */
    private String username;
    /**
     * Password
     */
    private String password;

    /**
     * Cellphone
     */
    private String cellphone;

    /**
     * Email
     */
    private String email;

    /**
     * Granted roles for user
     */
    private String[] roles;

    /**
     * Granted permissions for user
     */
    private String[] permissions;

    /**
     * Current logged in session by provider
     */
    private String provider;

    /**
     * Current logged in session by openId
     */
    private String openId;

    /**
     * Current session code
     */
    private Serializable code;

    /**
     * Extra information of open account connected to provider
     */
    private Map<String, Object> extraInfo;

    public UserInfo() {

    }

    public UserInfo(Serializable id, String username, String password, String cellphone, String email) {
        this.userId = id;
        this.username = username;
        this.password = password;
        this.cellphone = cellphone;
        this.email = email;
    }

    public UserInfo(Serializable id, String username, String password, String cellphone, String email, Map<String, Object> extraInfo) {
        this.userId = id;
        this.username = username;
        this.password = password;
        this.cellphone = cellphone;
        this.email = email;
        this.extraInfo = extraInfo;
    }

    public Serializable getUserId() {
        return userId;
    }

    public void setUserId(Serializable userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String[] getRoles() {
        return roles;
    }

    public void setRoles(String[] roles) {
        this.roles = roles;
    }

    public String[] getPermissions() {
        return permissions;
    }

    public void setPermissions(String[] permissions) {
        this.permissions = permissions;
    }

    public String getCellphone() {
        return cellphone;
    }

    public void setCellphone(String cellphone) {
        this.cellphone = cellphone;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getOpenId() {
        return openId;
    }

    public void setOpenId(String openId) {
        this.openId = openId;
    }

    public Serializable getCode() {
        return code;
    }

    public void setCode(Serializable code) {
        this.code = code;
    }

    public Map<String, Object> getExtraInfo() {
        return extraInfo;
    }

    public void setExtraInfo(Map<String, Object> extraInfo) {
        this.extraInfo = extraInfo;
    }

    @Override
    public String toString() {
        return "UserInfo{" +
                "userId=" + userId +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", cellphone='" + cellphone + '\'' +
                ", roles=" + Arrays.toString(roles) +
                ", permissions=" + Arrays.toString(permissions) +
                ", provider='" + provider + '\'' +
                ", openId='" + openId + '\'' +
                ", extraInfo=" + extraInfo +
                '}';
    }
}
