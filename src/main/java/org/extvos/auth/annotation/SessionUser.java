package org.extvos.auth.annotation;

import java.lang.annotation.*;

/**
 * 获取Shiro当前用户
 *
 * @author Mingcai SHEN
 * @see SessionUserArgumentResolver
 */
@Target({ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface SessionUser {
}
