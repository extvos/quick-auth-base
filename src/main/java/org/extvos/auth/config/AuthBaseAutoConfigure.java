package org.extvos.auth.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;

/**
 * @author Mingcai SHEN
 */
@ComponentScan("org.extvos.auth")
public class AuthBaseAutoConfigure {
    @Bean
    public Docket createAuthBaseDocket() {
        return new Docket(DocumentationType.SWAGGER_2)
                .groupName("鉴权认证服务")
                .apiInfo(new ApiInfoBuilder()
                        .title("鉴权认证服务")
                        .description("A basic user authentication and authorization lib.")
                        .contact(new Contact("Mingcai SHEN", "https://gitlab.inodes.cn/", "archsh@gmail.com"))
                        .termsOfServiceUrl("https://gitlab.inodes.cn/quickstart/java-scaffolds/quick-auth-base")
                        .version(getClass().getPackage().getImplementationVersion())
                        .build())
                .select()
                .apis(RequestHandlerSelectors.basePackage("org.extvos.auth"))
                .build();
    }
}
