package plus.extvos.auth.service;

import plus.extvos.common.exception.ResultException;

/**
 * @author Mingcai SHEN
 * <p>
 * SMSService provide the ability to send SMS Messages.
 */
public interface SMSService {
    /**
     * Send secret code via SMS
     *
     * @param phone cellphone number
     * @param code  code to be sent
     * @return true if sent
     * @throws ResultException if errors
     */
    boolean sendSecretCode(String phone, String code) throws ResultException;
}
