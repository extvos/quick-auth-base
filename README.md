# quick-auth-base

基础认证服务，基于`Shiro`提供用户登入登出接口，以及相关的用户操作接口。模块本身不存储用户数据信息，依赖于应用方注入实现了`org.extvos.auth.service.QuickAuthService`的bean完成用户信息的存取操作。



## 模块提供的接口

### `POST` `/auth/login` 用户登录接口

#### 请求参数：
- `username` 用户名
- `password` 用户密码
- `salt` 密码加扰盐（如果用户密码未加扰，则保持为空或不提供）
- `algorithm` 用户密码加扰算法（无盐则无需考虑，默认使用`MD5`），支持`MD5`,`SHA1`,`SHA-256`,`SHA-512`
- `captcha` 验证码（如果没有则不需要提供）
- `redirectUri` 登陆成功后跳转`URL`，若为空则返回`JSON`格式数据

请求参数支持`FORM`的方式提交，也支持以`JSON`的格式提交。

#### 返回数据：

```json
{
    "code": 20000,
    "data":{
        "username": "xxxxxx",
        "redirect": true|false
    }
}
```

如果请求的时候提供了`redirectUri`则直接跳转，不返回数据。

#### 异常结果：

```json
{
	"code": XXXXXX,
    "msg": "xxxxxxxxxxxx"
}
```

`code`列表：
- `40001` 验证码未提供
- `40002` 验证码无效
- `40003` 未提供加扰盐
- `40301` 账户未启用或禁用
- `40302` 账户被锁定
- `40303` 重试次数过多
- `40304` 用户名或密码无效
- `40401` 用户不存在
- `50000` 其他内部错误

### `POST` `/auth/logout` 用户登出接口

#### 请求参数
无
#### 返回结果
```json
{
  "code":20000,
  "data":"DONE"
}
```


### `GET` `/auth/captcha` 验证码接口

获取验证码，`png`格式的验证码以`Base64`的方式包含在`JSON`中。



### `GET` `/auth/captcha-image` 验证码图形接口

返回验证码图形，`png`格式。



### `POST` `/auth/register` 用户注册接口

注册用户



### `POST` `/auth/change-password` 用户更改密码接口

更改当前登录用户密码



## 模块提供的注解

### `@SessionUser` 当前会话用户

该注解用户常用的`Controller`方法参数之中，`Controller`方法无需调用`SecurityUtils`去获取当前用户信息，可以通过`@SessionUser`注解直接得到当前会话用户的用户名。

比如：

```Java
    @RequiresAuthentication
    @GetMapping("/example/by/user")
    public Result<String> exampleByUser(@SessionUser String username) {
        return Result.data(username).success();
    }
```



## `QuickAuthService`接口

接口指定了应用方使用模块时需要注入的Bean需实现的功能规格。

```Java
public interface QuickAuthService {
    /**
     * Get UserInfo by username
     *
     * @param name : username
     * @param checkEnabled: check if user enabled or not
     * @return UserInfo object
     * @throws RestletException when errors
     */
    UserInfo getUserByName(String name,boolean checkEnabled) throws RestletException;

    /**
     * Get UserInfo by id
     *
     * @param id of user
     * @param checkEnabled: check if user enabled or not
     * @return UserInfo
     * @throws RestletException when errors
     */
    UserInfo getUserById(Serializable id,boolean checkEnabled) throws RestletException;


    /**
     * Get user roles by id
     *
     * @param id userid
     * @return role list
     * @throws RestletException when errors
     */
    List<RoleInfo> getRoles(Serializable id) throws RestletException;

    /**
     * Get user permissions by id
     *
     * @param id userid
     * @return permission list
     * @throws RestletException when errors
     */
    List<PermissionInfo> getPermissions(Serializable id) throws RestletException;

    /**
     * Create new user info into database or other persistent storage
     *
     * @param username string
     * @param password string
     * @param params   extra properties of user.
     * @return Serializable user id
     * @throws RestletException when errors
     */
    Serializable createUserInfo(String username, String password, Map<String, Object> params) throws RestletException;


    /**
     * Update user info into database or other persistent storage
     *
     * @param username string
     * @param password string
     * @param params   extra properties of user.
     * @throws RestletException when errors
     */
    void updateUserInfo(String username, String password, Map<String, Object> params) throws RestletException;
}
```



## 相关配置

```yaml
quick:
  auth:
    base:
      secret: "quick"  # 用户模块自身数据加扰
      captcha-required: false # 是否强制需要验证码
      salt-required: false # 登录时密码是否需要强制加盐加扰
      register-allowed: false # 是否允许注册
```

