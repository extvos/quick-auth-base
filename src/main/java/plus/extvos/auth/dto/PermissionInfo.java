package plus.extvos.auth.dto;

import java.io.Serializable;

/**
 * @author Mingcai SHEN
 */
public class PermissionInfo  implements Serializable {
    private String code;
    private String desc;

    public PermissionInfo(String code, String desc) {
        this.code = code;
        this.desc = desc;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getDesc() {
        return desc;
    }

    public void setDesc(String desc) {
        this.desc = desc;
    }

    @Override
    public String toString() {
        return "PermissionInfo{" +
                "code='" + code + '\'' +
                ", desc='" + desc + '\'' +
                '}';
    }
}
