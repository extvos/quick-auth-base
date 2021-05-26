package org.extvos.auth.shiro;

import org.extvos.auth.dto.UserInfo;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;

/**
 * @author Mingcai SHEN
 */
public class QuickInfo implements AuthenticationInfo {
    private final String username;
    private final String password;
    private final SimplePrincipalCollection principalCollection;


    public QuickInfo(UserInfo info) {
        this(info.getUsername(), info.getPassword());
    }

    public QuickInfo(String un, String pw) {
        username = un;
        password = pw;
        principalCollection = new SimplePrincipalCollection();
        principalCollection.add(un, pw);
    }

    @Override
    public PrincipalCollection getPrincipals() {
        return principalCollection;
    }

    @Override
    public Object getCredentials() {
        return password;
    }

    public String getUsername() {
        return username;
    }
}
