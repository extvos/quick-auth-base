package plus.extvos.auth.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import plus.extvos.auth.handler.PermissionCollector;
import plus.extvos.common.Result;
import plus.extvos.common.exception.ResultException;

import java.util.List;

/**
 * @author Mingcai SHEN
 */
@Api(tags = {"鉴权辅助"})
@RequestMapping("/auth")
@RestController
public class HelperController {

    @ApiOperation("内置权限列表")
    @GetMapping("/auth/all-permissions")
    public Result<List<String>> getAllPermissions() throws ResultException {
        return Result.data(PermissionCollector.permissions()).success();
    }

    @ApiOperation("内置角色列表")
    @GetMapping("/auth/all-roles")
    public Result<List<String>> getAllRoles() throws ResultException {

        return Result.data(PermissionCollector.roles()).success();
    }
}
