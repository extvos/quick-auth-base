package plus.extvos.auth.config;

import com.google.code.kaptcha.impl.DefaultKaptcha;
import com.google.code.kaptcha.util.Config;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import java.util.Properties;

/**
 * @author Mingcai SHEN
 */
@Component
@Configuration
public class CaptchaConfig {

    // 图片边框
    @Value("${quick.auth.kaptcha.border:yes}")
    private String border;
    // 边框颜色
    @Value("${quick.auth.kaptcha.border-color:105,179,90}")
    private String borderColor;
    // 字体颜色
    @Value("${quick.auth.kaptcha.font-color:57,172,106}")
    private String fontColor;
    // 图片宽
    @Value("${quick.auth.kaptcha.width:150}")
    private String width;
    // 图片高
    @Value("${quick.auth.kaptcha.height:50}")
    private String height;
    // 字符集
    @Value("${quick.auth.kaptcha.chars:1234567890}")
    private String chars;
    // 字体大小
    @Value("${quick.auth.kaptcha.font-size:45}")
    private String fontSize;
    // session key
    @Value("${quick.auth.kaptcha.session-key:code}")
    private String sessionKey;
    // 验证码长度
    @Value("${quick.auth.kaptcha.code-length:4}")
    private String codeLength;
    // 字体
    @Value("${quick.auth.kaptcha.font-names:Serif,Sans-serif}")
    private String fontName;

    @Bean
    public DefaultKaptcha getDefaultKaptcha() {

        com.google.code.kaptcha.impl.DefaultKaptcha defaultKaptcha = new com.google.code.kaptcha.impl.DefaultKaptcha();

        Properties properties = new Properties();
        // 图片边框
        properties.setProperty("kaptcha.border", border);
        // 边框颜色
        properties.setProperty("kaptcha.border.color", borderColor);
//		 字体颜色
        properties.setProperty("kaptcha.textproducer.font.color", fontColor);
        // 图片宽
        properties.setProperty("kaptcha.image.width", width);
        // 图片高
        properties.setProperty("kaptcha.image.height", height);
        // 字符集
        properties.setProperty("kaptcha.textproducer.char.string", chars);
        // 字体大小
        properties.setProperty("kaptcha.textproducer.font.size", fontSize);
        // session key
        properties.setProperty("kaptcha.session.key", sessionKey);
        // 验证码长度
        properties.setProperty("kaptcha.textproducer.char.length", codeLength);
        // 字体
        properties.setProperty("kaptcha.textproducer.font.names", fontName);
        Config config = new Config(properties);
        defaultKaptcha.setConfig(config);

        return defaultKaptcha;
    }
}
