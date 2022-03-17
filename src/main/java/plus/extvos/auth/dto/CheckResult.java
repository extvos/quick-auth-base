package plus.extvos.auth.dto;

import io.swagger.annotations.ApiModel;

@ApiModel("检查结果")
public class CheckResult {
    private String checkBy;
    private Boolean exists;

    public CheckResult() {
    }

    public CheckResult(String checkBy, Boolean exists) {
        this.checkBy = checkBy;
        this.exists = exists;
    }

    public String getCheckBy() {
        return checkBy;
    }

    public void setCheckBy(String checkBy) {
        this.checkBy = checkBy;
    }

    public Boolean getExists() {
        return exists;
    }

    public void setExists(Boolean exists) {
        this.exists = exists;
    }
}
