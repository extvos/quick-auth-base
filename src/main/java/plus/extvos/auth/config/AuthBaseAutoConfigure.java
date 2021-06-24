package plus.extvos.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;

/**
 * @author Mingcai SHEN
 */
@ComponentScan("plus.extvos.auth")
public class AuthBaseAutoConfigure {
    @Bean
    public Docket createAuthBaseDocket() {
        return new Docket(DocumentationType.SWAGGER_2)
            .groupName("鉴权认证服务")
            .apiInfo(new ApiInfoBuilder()
                .title("鉴权认证服务")
                .description("A basic user authentication and authorization lib.")
                .contact(new Contact("Mingcai SHEN", "https://github.com/", "archsh@gmail.com"))
                .termsOfServiceUrl("https://github.com/quickstart/java-scaffolds/quick-auth-base")
                .version(getClass().getPackage().getImplementationVersion())
                .build())
            .select()
            .apis(RequestHandlerSelectors.basePackage("plus.extvos.auth"))
            .build();
    }
}
