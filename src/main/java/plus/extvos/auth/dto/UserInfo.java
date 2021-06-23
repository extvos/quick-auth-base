package plus.extvos.auth.dto;

import java.io.Serializable;
import java.util.Map;

/**
 * @author Mingcai SHEN
 */
public class UserInfo implements Serializable {
    private Serializable userId;
    private String username;
    private String password;
    private String cellphone;
    private String[] roles;
    private String[] permissions;
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

    public Map<String, Object> getExtraInfo() {
        return extraInfo;
    }

    public void setExtraInfo(Map<String, Object> extraInfo) {
        this.extraInfo = extraInfo;
    }
}
