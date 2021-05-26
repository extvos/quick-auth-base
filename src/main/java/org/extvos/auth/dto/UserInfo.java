package org.extvos.auth.dto;

import java.io.Serializable;

/**
 * @author Mingcai SHEN
 */
public class UserInfo implements Serializable {
    private Serializable id;
    private String username;
    private String password;
    private String[] roles;
    private String[] permissions;

    public UserInfo(Serializable id, String username, String password) {
        this.id = id;
        this.username = username;
        this.password = password;
    }

    public Serializable getId() {
        return id;
    }

    public void setId(Serializable id) {
        this.id = id;
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
}
