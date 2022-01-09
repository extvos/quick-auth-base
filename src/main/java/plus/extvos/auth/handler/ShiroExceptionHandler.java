package plus.extvos.auth.handler;

import org.apache.shiro.ShiroException;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.UnauthorizedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.HandlerMethod;
import plus.extvos.common.ResultCode;
import plus.extvos.common.Result;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Mingcai SHEN
 */
@RestControllerAdvice
public class ShiroExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ShiroExceptionHandler.class);

    @ExceptionHandler(value = {ShiroException.class})
    public Result<?> exception(HttpServletRequest request, ShiroException e, HandlerMethod handlerMethod) {
        log.warn("exception:> {} {} ({}) > {}",
            request.getMethod(), request.getRequestURI(), handlerMethod.getMethod().getName(), e.getMessage());

        if (e instanceof UnauthenticatedException) {
            return Result.message("未认证").failure(ResultCode.UNAUTHORIZED);
        }
        if (e instanceof UnauthorizedException) {
            return Result.message("未授权").failure(ResultCode.FORBIDDEN);
        }
        if (e instanceof AuthorizationException) {
            return Result.message("认证失败").failure(ResultCode.UNAUTHORIZED);
        }

        return Result.message("认证出错").failure(ResultCode.CONFLICT);
    }
}
