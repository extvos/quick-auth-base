package org.extvos.auth.shiro;

import org.extvos.auth.config.QuickAuthConfig;
import org.extvos.auth.service.QuickFilterCustomizer;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import javax.servlet.Filter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author Mingcai SHEN
 */
@Component
public class ShiroConfig {

    private static final Logger log = LoggerFactory.getLogger(ShiroConfig.class);

    @Autowired(required = false)
    private QuickFilterCustomizer[] qfCustomizers;

    @Autowired
    private QuickAuthConfig baseAuthConfig;

    @Bean
    public CacheManager getCacheManager() {
        return new MemoryConstrainedCacheManager();
//        EhCacheManager em = new EhCacheManager();
//        em.setCacheManagerConfigFile("classpath:ehcache-shiro.xml");
//        return em;
    }




    /**
     * credential matcher
     */
    @Bean
    public CredentialsMatcher quickCredentialsMatcher() {
        return new QuickMatcher();
    }

    /**
     * quickRealm
     *
     * @param cacheManager
     * @return
     */
    @Bean
    public Realm quickRealm(CacheManager cacheManager) {
        QuickRealm customRealm = new QuickRealm();
        customRealm.setCacheManager(cacheManager);
        customRealm.setCredentialsMatcher(quickCredentialsMatcher());
        return customRealm;
    }

    /**
     * Configure session manager
     */
    @Bean
    public SessionManager sessionManager() {
        return new QuickSessionManager();
//        shiroSessionManager.setSessionDAO(redisSessionDAO());
//        return sessionManager;
    }

    /**
     * 权限管理，配置主要是Realm的管理认证
     *
     * @return SecurityManager
     */
    @Bean
    public SecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setCacheManager(getCacheManager());
        securityManager.setRealm(quickRealm(getCacheManager()));
        securityManager.setSessionManager(sessionManager());
        return securityManager;
    }

    /**
     * make the ShiroFilterFactoryBean
     *
     * @param securityManager of system securityManager
     * @return a ShiroFilterFactoryBean
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);

        log.debug("Building shiroFilterFactoryBean ...");
        log.debug(" ... {}", baseAuthConfig);
        if (null != baseAuthConfig) {
            log.debug(" ... getSecret> {}", baseAuthConfig.getSecret());
            log.debug(" ... getSmsCodeLength> {}", baseAuthConfig.getSmsCodeLength());
            log.debug(" ... isCaptchaRequired> {}", baseAuthConfig.isCaptchaRequired());
            log.debug(" ... isPhoneRequired> {}", baseAuthConfig.isPhoneRequired());
            log.debug(" ... isSaltRequired> {}", baseAuthConfig.isSaltRequired());
            log.debug(" ... isRegisterAllowed> {}", baseAuthConfig.isRegisterAllowed());
        }

        // Set Filter
        Map<String, Filter> filters = new LinkedHashMap<>();
        filters.put("auth", new QuickFilter());
        shiroFilterFactoryBean.setFilters(filters);

        //登录
        shiroFilterFactoryBean.setLoginUrl(System.getProperty("server.servlet.context-path") + "/" + "auth/login");
        //首页
//        shiroFilterFactoryBean.setSuccessUrl("/index");
        //错误页面，认证不通过跳转
//        shiroFilterFactoryBean.setUnauthorizedUrl("/error");

        shiroFilterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition().getFilterChainMap());
        return shiroFilterFactoryBean;
    }

    /**
     * make a ShiroFilterChainDefinition
     *
     * @return a new ShiroFilterChainDefinition
     */
    @Bean
    public ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        String ctxPath = System.getProperty("server.servlet.context-path") == null ? "" : System.getProperty("server.servlet.context-path");
        // chainDefinition.addPathDefinition(ctxPath + "/" + "auth/logout", "logout");
        // Swagger
        chainDefinition.addPathDefinition(ctxPath + "/" + "swagger-ui.html", "anon");
        chainDefinition.addPathDefinition(ctxPath + "/" + "doc.html", "anon");
        chainDefinition.addPathDefinition(ctxPath + "/" + "webjars/**", "anon");
        chainDefinition.addPathDefinition(ctxPath + "/" + "v2/api-docs", "anon");
        chainDefinition.addPathDefinition(ctxPath + "/" + "swagger-resources/**", "anon");

        // Login
        chainDefinition.addPathDefinition(ctxPath + "/" + "auth/user/create", "anon");

        if (null != qfCustomizers) {
            for (QuickFilterCustomizer qfCustomizer : qfCustomizers) {
                log.debug("QuickFilterCustomizer:> {} ", qfCustomizer);
                if (null != qfCustomizer.anons()) {
                    for (String s : qfCustomizer.anons()) {
                        log.debug("QuickFilterCustomizer:> add anon: {} ", s);
                        chainDefinition.addPathDefinition(s, "anon");
                    }
                }

                if (null != qfCustomizer.auths()) {
                    for (String s : qfCustomizer.auths()) {
                        log.debug("QuickFilterCustomizer:> add auth: {} ", s);
                        chainDefinition.addPathDefinition(s, "auth");
                    }
                }
            }
        }
        // all other path will be added as non-auth required by default, for application level,
        // please inject a QuickFilterCustomizer bean to customize, or use annotations of Shiro.
        chainDefinition.addPathDefinition("/**", "anon");
        return chainDefinition;
    }

    /**
     * @param securityManager
     * @return
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }
}