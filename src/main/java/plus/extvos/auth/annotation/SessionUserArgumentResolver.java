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
import plus.extvos.auth.service.QuickAuthService;
import plus.extvos.common.exception.ResultException;
import plus.extvos.common.utils.SpringContextHolder;

/**
 * {@link SessionUser} 注解的解析
 *
 * @author Mingcai SHEN
 */
public class SessionUserArgumentResolver implements HandlerMethodArgumentResolver {

    private QuickAuthService quickAuthService;

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
        if (supportsParameter(parameter) && (subject.isAuthenticated() || subject.isRemembered())) {

            if (parameter.getParameterType().equals(String.class)) {
                return subject.getPrincipal();
            } else if (parameter.getParameterType().equals(UserInfo.class)) {
                Session session = subject.getSession();
                try {
                    UserInfo userInfo = (UserInfo) session.getAttribute(UserInfo.USER_INFO_KEY);
                    if (null == userInfo) {
                        if (null == quickAuthService) {
                            quickAuthService = SpringContextHolder.getBean(QuickAuthService.class);
                        }
//                        if (null != quickAuthService) {
                        userInfo = quickAuthService.getUserByName(subject.getPrincipal().toString(), true);
                        session.setAttribute(UserInfo.USER_INFO_KEY, userInfo);
//                        }
                    }
                    return userInfo;
                } catch (ResultException e) {
                    return null;
                }
            }
        }
        return null;
    }
}
