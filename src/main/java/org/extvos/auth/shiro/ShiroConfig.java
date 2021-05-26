package org.extvos.auth.shiro;

import org.extvos.auth.config.QuickAuthConfig;
import org.extvos.auth.service.QuickFilterCustomizer;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author Mingcai SHEN
 */
@Configuration
public class ShiroConfig {

    private static final Logger log = LoggerFactory.getLogger(ShiroConfig.class);

    @Autowired(required = false)
    QuickFilterCustomizer qfCustomizer;

    @Autowired
    private QuickAuthConfig baseAuthConfig;

    @Bean
    public CacheManager getCacheManager() {
        return new MemoryConstrainedCacheManager();
//        EhCacheManager em = new EhCacheManager();
//        em.setCacheManagerConfigFile("classpath:ehcache-shiro.xml");
//        return em;
    }


    @Bean(name = "lifecycleBeanPostProcessor")
    public LifecycleBeanPostProcessor getLifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

    @Bean
    @ConditionalOnMissingBean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator defaultAAP = new DefaultAdvisorAutoProxyCreator();
        defaultAAP.setProxyTargetClass(true);
        return defaultAAP;
    }


    /**
     * 凭证匹配器 （由于我们的密码校验交给Shiro的SimpleAuthenticationInfo进行处理了
     * 所以我们需要修改下doGetAuthenticationInfo中的代码; )
     */
    @Bean
    public QuickMatcher quickCredentialsMatcher() {
        // BaseAuthConfig cfg = SpringContextHolder.getBean(BaseAuthConfig.class);
        QuickMatcher matcher = new QuickMatcher();
//        matcher.setAlgorithm(baseAuthConfig.getHashAlgorithm());
//        matcher.setIterations(baseAuthConfig.getHashIterations());
        return matcher;
    }

    //将自己的验证方式加入容器
    @Bean
    public QuickRealm quickRealm(CacheManager cacheManager) {
        QuickRealm customRealm = new QuickRealm();
        customRealm.setCacheManager(cacheManager);
        customRealm.setCredentialsMatcher(quickCredentialsMatcher());
        return customRealm;
    }

    //权限管理，配置主要是Realm的管理认证
    @Bean
    public SecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setCacheManager(getCacheManager());
        securityManager.setRealm(quickRealm(getCacheManager()));
        return securityManager;
    }

    // Filter工厂，设置对应的过滤条件和跳转条件
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);

        Map<String, String> map = new LinkedHashMap<>();
//        Map<String, String> map = new HashMap<>(); // DO NOT USE IT !!!

        // 登出
//        map.put("/auth/logout", "logout");
//        map.put("/login", "login");

        // Swagger
        map.put("/swagger-ui.html", "anon");
        map.put("/doc.html", "anon");
        map.put("/webjars/**", "anon");
        map.put("/v2/api-docs", "anon");
        map.put("/swagger-resources/**", "anon");

        // Login
        map.put("/auth/login", "anon");

        map.put("/oauth/authorize", "auth");
        map.put("/oauth/token", "anon");
        map.put("/oauth/refresh", "anon");
        map.put("/auth/user/create", "anon");

        // 对所有用户认证
        map.put("/**", "anon");
        if (qfCustomizer != null) {
            String[] anons = qfCustomizer.anons();
            String[] auths = qfCustomizer.auths();
            if (anons != null) {
                for (String s : anons) {
                    log.debug("ShiroFilterFactoryBean:> add anon: {}", s);
                    map.put(s, "anon");
                }
            }
            if (auths != null) {
                for (String s : auths) {
                    log.debug("ShiroFilterFactoryBean:> add auth: {}", s);
                    map.put(s, "auth");
                }
            }
        }

        // Set Filter
        Map<String, Filter> filters = new LinkedHashMap<>();
        filters.put("auth", new QuickFilter());
        shiroFilterFactoryBean.setFilters(filters);

        //登录
        shiroFilterFactoryBean.setLoginUrl("/auth/login");
        //首页
        shiroFilterFactoryBean.setSuccessUrl("/index");
        //错误页面，认证不通过跳转
        shiroFilterFactoryBean.setUnauthorizedUrl("/error");
        shiroFilterFactoryBean.setFilterChainDefinitionMap(map);
        return shiroFilterFactoryBean;
    }


    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }
}