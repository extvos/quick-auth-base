package plus.extvos.auth.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
    @ConditionalOnProperty(prefix = "spring.swagger", name = "disabled", havingValue = "false", matchIfMissing = true)
    public Docket createAuthBaseDocket() {
        return new Docket(DocumentationType.SWAGGER_2)
            .groupName("鉴权认证服务")
            .apiInfo(new ApiInfoBuilder()
                .title("鉴权认证服务")
                .description("A basic user authentication and authorization lib.")
                .contact(new Contact("Mingcai SHEN", "https://github.com/archsh/", "archsh@gmail.com"))
                .termsOfServiceUrl("https://github.com/extvos/quickstart/raw/develop/LICENSE")
                .version(getClass().getPackage().getImplementationVersion())
                .build())
            .select()
            .apis(RequestHandlerSelectors.basePackage("plus.extvos.auth"))
            .build();
    }
}
