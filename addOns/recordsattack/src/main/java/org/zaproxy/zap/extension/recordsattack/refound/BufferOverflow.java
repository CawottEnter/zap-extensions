/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.recordsattack.refound;

import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.recordsattack.SeleniumUsage;
import org.zaproxy.zap.extension.recordsattack.serializableHelper.AuthentificationSerializable;
import org.zaproxy.zap.extension.recordsattack.serializableHelper.HistoryReferenceSerializer;

public class BufferOverflow extends Scanner {

    BufferOverflow(AuthentificationSerializable authentification, SeleniumUsage seleniumUsage) {
        super(authentification, seleniumUsage);
        // TODO Auto-generated constructor stub
    }

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.bufferoverflow.";

    private static final int PLUGIN_ID = 30001;
    private static Logger log = Logger.getLogger(BufferOverflow.class);

    public String getOther() {
        return Constant.messages.getString(MESSAGE_PREFIX + "other");
    }

    /*
     * This method is called by the active scanner for each GET and POST parameter
     * for every page
     *
     * @see
     * org.parosproxy.paros.core.scanner.AbstractAppParamPlugin#scan(org.parosproxy.
     * paros.network.HttpMessage, java.lang.String, java.lang.String)
     */
    public void scan(HttpMessage msg, String param, String value) {
        setParameter(msg, param, value);
        /*
        if (msg.getResponseHeader().getStatusCode()
                == HttpStatusCode.INTERNAL_SERVER_ERROR) // Check to see if
        // the page closed
        // initially
        {
            return; // Stop
        }

        try {
            // This is where you change the 'good' request to attack the application
            // You can make multiple requests if needed
            String checkStringHeader1 = "Connection: close"; // Un natural close
            // Always use getNewMsg() for each new request

            String returnAttack = randomCharacterString(2100);
            setParameter(msg, param, returnAttack);
            try {

                HttpSender httpSender =
                        new HttpSender(
                                Model.getSingleton().getOptionsParam().getConnectionParam(),
                                true,
                                HttpSender.MANUAL_REQUEST_INITIATOR);
                httpSender.sendAndReceive(msg);
            } catch (UnknownHostException ex) {
                if (log.isDebugEnabled())
                    log.debug(
                            "Caught "
                                    + ex.getClass().getName()
                                    + " "
                                    + ex.getMessage()
                                    + " when accessing: "
                                    + msg.getRequestHeader().getURI().toString()
                                    + "\n The target may have replied with a poorly formed redirect due to our input.");
                return; // Something went wrong no point continuing
            }

            HttpResponseHeader requestReturn = msg.getResponseHeader();
            // This is where BASE baseResponseBody was you detect potential vulnerabilities
            // in the
            // response
            String chkerrorheader = requestReturn.getHeadersAsString();
            log.debug("Header: " + chkerrorheader);
            if (msg.getResponseHeader().getStatusCode() == HttpStatusCode.INTERNAL_SERVER_ERROR
                    && chkerrorheader.contains(checkStringHeader1)) {
                log.debug("Found Header");
                bingo(
                        getRisk(),
                        Alert.CONFIDENCE_MEDIUM,
                        msg.getRequestHeader().getURI().toString(),
                        param,
                        msg.getRequestHeader().toString(),
                        this.getOther(),
                        msg);
                return;
            }

            return;
        } catch (URIException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to send HTTP message, cause: " + e.getMessage());
            }
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
        */
    }

    private void bingo(
            int risk,
            int confidenceMedium,
            String string,
            String param,
            String string2,
            String other,
            HttpMessage msg) {}

    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    private String randomCharacterString(int length) {
        StringBuilder sb1 = new StringBuilder(length + 1);
        int counter = 0;
        int character = 0;
        while (counter < length) {
            character = 65 + (int) (Math.random() * 57);

            while (character > 90 && character < 97) {
                character = 65 + (int) (Math.random() * 57);
            }

            counter = counter + 1;
            sb1.append((char) character);
        }
        return sb1.toString();
    }

    @Override
    public void scan(List<HistoryReferenceSerializer> historyReference, String parameters) {
        // TODO Auto-generated method stub

    }
}
