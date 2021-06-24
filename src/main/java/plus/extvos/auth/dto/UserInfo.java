package plus.extvos.auth.dto;

import java.io.Serializable;
import java.util.Map;

/**
 * UserInfo presented information of logged in user with basic properties and
 * connected open account properties if current session is logged via open account.
 *
 * @author Mingcai SHEN
 */
public class UserInfo implements Serializable {
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
     * Extra information of open account connected to provider
     */
    private Map<String, Object> extraInfo;

    public UserInfo(Serializable id, String username, String password, String cellphone) {
        this.userId = id;
        this.username = username;
        this.password = password;
        this.cellphone = cellphone;
    }

    public UserInfo(Serializable id, String username, String password, String cellphone, Map<String, Object> extraInfo) {
        this.userId = id;
        this.username = username;
        this.password = password;
        this.cellphone = cellphone;
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

    public Map<String, Object> getExtraInfo() {
        return extraInfo;
    }

    public void setExtraInfo(Map<String, Object> extraInfo) {
        this.extraInfo = extraInfo;
    }
}
