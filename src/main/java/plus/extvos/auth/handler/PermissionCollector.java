package plus.extvos.auth.handler;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class PermissionCollector implements BeanPostProcessor {

    @Value("${quick.auth.permission-collector.disable:false}")
    private Boolean disable;

    private static final Set<String> permSet = new LinkedHashSet<>();
    private static final Set<String> roleSet = new LinkedHashSet<>();

    public static List<String> permissions() {
        return permSet.stream().sorted(String::compareTo).collect(Collectors.toList());
    }

    public static List<String> roles() {
        return roleSet.stream().sorted(String::compareTo).collect(Collectors.toList());
    }

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        if (disable == null || !disable) {
            Method[] methods = bean.getClass().getMethods();
            for (Method method : methods) {
                if (method.isAnnotationPresent(RequiresPermissions.class)) {
                    RequiresPermissions perms = method.getAnnotation(RequiresPermissions.class);
                    permSet.addAll(Arrays.asList(perms.value()));
                }
                if (method.isAnnotationPresent(RequiresRoles.class)) {
                    RequiresRoles roles = method.getAnnotation(RequiresRoles.class);
                    roleSet.addAll(Arrays.asList(roles.value()));
                }
            }
            if (bean.getClass().isAnnotationPresent(RequiresPermissions.class)) {
                RequiresPermissions perms = bean.getClass().getAnnotation(RequiresPermissions.class);
                permSet.addAll(Arrays.asList(perms.value()));
            }
            if (bean.getClass().isAnnotationPresent(RequiresRoles.class)) {
                RequiresRoles roles = bean.getClass().getAnnotation(RequiresRoles.class);
                roleSet.addAll(Arrays.asList(roles.value()));
            }
        }
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }
}
