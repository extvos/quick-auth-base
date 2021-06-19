package org.extvos.auth.annotation;

import org.extvos.auth.dto.UserInfo;
import org.extvos.auth.service.QuickAuthService;
import org.extvos.restlet.exception.RestletException;
import org.extvos.restlet.utils.SpringContextHolder;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * {@link SessionUser} 注解的解析
 *
 * @author Mingcai SHEN
 */
public class SessionUserArgumentResolver implements HandlerMethodArgumentResolver {

    private QuickAuthService quickAuthService;

    private QuickAuthService getAuthService() {
        if (quickAuthService == null) {
            quickAuthService = SpringContextHolder.getBean(QuickAuthService.class);
        }
        return quickAuthService;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(SessionUser.class);
    }

    @Override
    public Object resolveArgument(MethodParameter parameter,
                                  ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest,
                                  WebDataBinderFactory binderFactory) throws Exception {
        Subject subject = SecurityUtils.getSubject();
        if (null == subject) {
            return null;
        }
        if (supportsParameter(parameter) && subject.isAuthenticated()) {
            if (parameter.getParameterType().equals(String.class)) {
                return subject.getPrincipal();
            } else if (parameter.getParameterType().equals(UserInfo.class)) {
                try {
                    return getAuthService().getUserByName(subject.getPrincipal().toString(), false);
                } catch (RestletException e) {
                    return null;
                }
            }
        }
        return subject.getPrincipal();
    }
}
