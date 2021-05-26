package org.extvos.auth.shiro;

import org.extvos.auth.config.QuickAuthConfig;
import org.extvos.auth.utils.CredentialHash;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author Mingcai SHEN
 */
public class QuickMatcher implements CredentialsMatcher {

    private static final Logger log = LoggerFactory.getLogger(QuickMatcher.class);

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        log.debug("doCredentialsMatch:> {}, {}", token, info);
        if (token instanceof QuickToken) {
            log.debug("doCredentialsMatch:> QuickToken {} {} ", token, ((QuickToken) token).getSalt());
        }
        if (info instanceof QuickInfo) {
            log.debug("doCredentialsMatch:> QuickInfo {} ", info);
        }

        if (token instanceof QuickToken && info instanceof QuickInfo) {
            QuickInfo quickInfo = (QuickInfo) info;
            QuickToken quickToken = (QuickToken) token;
            if (quickToken.getSalt() != null && !quickToken.getSalt().isEmpty()) {
                log.debug("doCredentialsMatch:> salted hash matching ... ");
                String algorithm = "MD5";
                if (quickToken.getAlgorithm() != null && !quickToken.getAlgorithm().isEmpty()) {
                    algorithm = quickToken.getAlgorithm();
                }
                try {
                    String nk = CredentialHash.salt(quickToken.getSalt())
                        .password(quickInfo.getCredentials().toString())
                        .algorithm(algorithm).encrypt();
                    return quickToken.getPassword().equals(nk);
                } catch (Exception e) {
                    log.error("doCredentialsMatch:> encrypt failed:", e);
                    return false;
                }

            }
        }
        log.debug("doCredentialsMatch:> simple matching ... ");
        return token.getPrincipal().equals(info.getPrincipals().getPrimaryPrincipal()) && token.getCredentials().equals(info.getCredentials());
//        return false;
    }
}
