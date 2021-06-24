package plus.extvos.auth.annotation;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import plus.extvos.auth.dto.UserInfo;
import plus.extvos.restlet.exception.RestletException;

/**
 * {@link SessionUser} 注解的解析
 *
 * @author Mingcai SHEN
 */
public class SessionUserArgumentResolver implements HandlerMethodArgumentResolver {

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
        Session session = subject.getSession();
        if (supportsParameter(parameter) && subject.isAuthenticated()) {
            if (parameter.getParameterType().equals(String.class)) {
                return subject.getPrincipal();
            } else if (parameter.getParameterType().equals(UserInfo.class)) {
                try {
                    return (UserInfo) session.getAttribute(UserInfo.USER_INFO_KEY);
                } catch (RestletException e) {
                    return null;
                }
            }
        }
        return subject.getPrincipal();
    }
}
