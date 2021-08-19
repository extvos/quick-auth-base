package plus.extvos.auth.service;

import java.io.Serializable;
import java.util.Map;

public interface UserRegisterHook {
    String OPEN = "open";
    String ADMIN = "admin";
    String OAUTH = "oauth";

    boolean preRegister(String username, String password, Map<String, Object> params, String source);

    default short defaultStatus(String source) {
        return 0;
    }

    default String[] defaultPermissions(String source) {
        return null;
    }

    default String[] defaultRoles(String source) {
        return null;
    }

    void postRegister(Serializable userId, String source);
}
