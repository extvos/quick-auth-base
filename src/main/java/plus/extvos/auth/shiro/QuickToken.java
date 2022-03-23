package plus.extvos.auth.shiro;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.shiro.authc.AuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.Calendar;
import java.util.Date;

/**
 * @author Mingcai SHEN
 */
public class QuickToken implements AuthenticationToken, Serializable {
    private String username;
    private String password;
    private String salt;
    private String algorithm;
    private String[] roles;
    private String[] permissions;
    private boolean signed;
    private boolean rememberMe;

    private static final Logger log = LoggerFactory.getLogger(QuickToken.class);

    public QuickToken(HttpServletRequest request, String secret) {
        String qts = request.getHeader("QUICK-AUTH");
        if (qts.isEmpty()) {
            for (Cookie ckd : request.getCookies()) {
                if (ckd.getName().equals("QUICK-AUTH")) {
                    qts = ckd.getValue();
                    log.debug(" get token from cookie ...");
                }
            }
        } else {
            log.debug(" get token from header ...");
        }
        if (!qts.isEmpty()) {
            QuickToken qt = fromJwt(qts, secret);
            if (null != qt) {
                username = qt.username;
                password = qt.password;
                roles = qt.roles;
                permissions = qt.permissions;
                signed = true;
            }
        }
    }

    public QuickToken(String un, String pw, String[] rs, String[] ps) {
        username = un;
        password = pw;
        roles = rs;
        permissions = ps;
    }

    public QuickToken(String un, String pw, String alg, String salt) {
        username = un;
        password = pw;
        algorithm = alg;
        this.salt = salt;
    }

    public String toJwt(String secret, int expires) {
        Algorithm alg = Algorithm.HMAC256(secret);
        Calendar cld = Calendar.getInstance();
        cld.add(Calendar.SECOND, (int) expires);
        Date dt = cld.getTime();
        return JWT.create()
                .withIssuer("quick-auth")
                .withClaim("username", username)
                .withClaim("password", password)
                .withClaim("salt", salt)
                .withClaim("algorithm", algorithm)
                .withArrayClaim("roles", roles)
                .withArrayClaim("permissions", permissions)
                .withExpiresAt(dt).sign(alg);
    }

    public static QuickToken fromJwt(String jwt, String secret) {
        Algorithm alg = Algorithm.HMAC256(secret);
        JWTVerifier verifier = JWT.require(alg)
                .withIssuer("quick-auth")
                .build(); //Reusable verifier instance
        try {
            DecodedJWT djwt = verifier.verify(jwt);
            QuickToken qt = new QuickToken(
                    djwt.getClaim("username").asString(),
                    djwt.getClaim("password").asString(),
                    djwt.getClaim("algorithm").asString(),
                    djwt.getClaim("salt").asString()
            );
            qt.signed = true;
            return qt;
        } catch (JWTVerificationException e) {
            log.error(" {}", e.getMessage());
            return null;
        }
    }

    @Override
    public Object getPrincipal() {
        return getUsername();
    }

    @Override
    public Object getCredentials() {
        return getPassword();
    }

    public void clear() {
        username = null;
        password = null;
        roles = null;
        permissions = null;
        signed = false;
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

    public boolean isSigned() {
        return signed;
    }

    public void setSigned(boolean signed) {
        this.signed = signed;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public boolean isRememberMe() {
        return rememberMe;
    }

    public void setRememberMe(boolean rememberMe) {
        this.rememberMe = rememberMe;
    }
}
