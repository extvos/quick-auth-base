package org.extvos.auth.service;

import org.extvos.restlet.exception.RestletException;

/**
 * @author shenmc
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
     * @throws RestletException if errors
     */
    boolean sendSecretCode(String phone, String code) throws RestletException;
}
