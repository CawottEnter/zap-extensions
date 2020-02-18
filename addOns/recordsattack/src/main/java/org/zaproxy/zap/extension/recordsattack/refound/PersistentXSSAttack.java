/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.recordsattack.SeleniumUsage;
import org.zaproxy.zap.extension.recordsattack.serializableHelper.AuthentificationSerializable;
import org.zaproxy.zap.extension.recordsattack.serializableHelper.HistoryReferenceSerializer;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

public class PersistentXSSAttack extends Scanner {

    public PersistentXSSAttack(
            AuthentificationSerializable authentification, SeleniumUsage seleniumUsage) {

        super(authentification, seleniumUsage);
        // TODO Auto-generated constructor stub
    }

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.testpersistentxssattack.";

    private static final String[] GENERIC_SCRIPT_ALERT = {
        /*
        "test :)", "<script>alert(1);</script>", "\"><inpu/onmouseover=alert(", "plouf"

             */
        "hello", "tootttt", "test3",
    };
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_8");
    private static Logger logger = Logger.getLogger(PersistentXSSAttack.class);

    /*
    """

    public void scan(List<HistoryReference> historyReference, String parameter) {
        boolean vulnerable = false;
        int finish = 0;
        while (!vulnerable && finish < GENERIC_SCRIPT_ALERT.length) {
            String payload = GENERIC_SCRIPT_ALERT[finish];
            TreeSet<HtmlParameter> cookies = authentification();
            for (HistoryReference reference : historyReference) {
                HttpMessage message;
                try {
                    logger.info("PLOUFFFF43");
                    logger.info("finish = " + finish);
                    logger.info("GENERIC_SCRIPT_ALERT = " + GENERIC_SCRIPT_ALERT.length);

                    message = reference.getHttpMessage();

                    HttpMessage sourceMsg2 = message.cloneRequest();
                    sourceMsg2.setCookieParams(cookies);
                    String method = sourceMsg2.getRequestHeader().getMethod();
                    setParameter(sourceMsg2, parameter, payload);
                    httpSender.sendAndReceive(sourceMsg2);

                    ExtensionHistory extHistory =
                            ((ExtensionHistory)
                                    Control.getSingleton()
                                            .getExtensionLoader()
                                            .getExtension(ExtensionHistory.NAME));
                    // sourceMsg2.setNote("Test avec :" + payload);
                    extHistory.addHistory(sourceMsg2, HistoryReference.TYPE_PROXIED);
                    cookies = sourceMsg2.getCookieParams();
                    // TODO a modifier apres le test
                    // vulnerable = true;
                } catch (DatabaseException | IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
            finish++;
        }
        logger.info("Fin de PersistentXSSAttack");
    }

    """*/

    public void scan(List<HistoryReferenceSerializer> historyReference, String parameter) {

        logger.info("RENTRER DANS SCAN PERSISTENTXSS");
        logger.info("generic size is" + GENERIC_SCRIPT_ALERT.length);
        seleniumUsage.addObserver();

        for (int finish = 0; finish < GENERIC_SCRIPT_ALERT.length - 1; finish++) {
            logger.info("finisj is " + finish);

            seleniumUsage.authentification();
            int _acc = 0;
            for (HistoryReferenceSerializer reference : historyReference) {
                HttpMessage message = null;

                _acc++;
                message = reference.getMessage().toHttpMessage();
                String payload = GENERIC_SCRIPT_ALERT[finish];
                HttpMessage sourceMsg2 = message.cloneRequest();
                setParameter(sourceMsg2, parameter, payload);
                logger.info("ONPUT DANS SCAN PERSISTENTXSS");
                logger.info("Il reste  " + (historyReference.size() - _acc));
                try {
                    Thread.sleep(4000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                this.seleniumUsage._executeJS(sourceMsg2);
            }
            //  seleniumUsage.resetSelenium();
        }
    }
}
