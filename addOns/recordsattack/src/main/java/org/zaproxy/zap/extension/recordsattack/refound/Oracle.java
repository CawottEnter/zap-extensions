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

import java.io.IOException;
import java.util.List;
import java.util.TreeSet;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.recordsattack.Authentification;

public class Oracle extends Scanner {
    private static final Logger logger = Logger.getLogger(Oracle.class);
    private int size_max_input = 0;

    public Oracle(Authentification authentification, String id_session, HttpSender httpSender) {
        super(authentification, id_session, httpSender);
        // TODO Auto-generated constructor stub
    }

    @Override
    public void scan(List<HistoryReference> historyReference, String parameters) {
        logger.info("Rentre dans scan Oracle");
        // En premier nous allons chercher la taille maximum accepte par le champ
        boolean size_max_done = false;
        String bufferSize = "";
        while (!size_max_done) {
            for (int i = 0; i < size_max_input; i++) bufferSize.concat("A");

            TreeSet<HtmlParameter> cookies = authentification();
            HttpMessage sourceMsg2 = null;
            for (HistoryReference reference : historyReference) {
                logger.info("T2");

                try {
                    HttpMessage message = reference.getHttpMessage();
                    sourceMsg2 = message.cloneRequest();
                    sourceMsg2.setCookieParams(cookies);

                    logger.info("Before : " + sourceMsg2.getRequestBody().toString());
                    setParameter(sourceMsg2, parameters, "to");
                    logger.info("After : " + sourceMsg2.getRequestBody().toString());

                    logger.info("T3");
                    /*
                    if (getParamNames(sourceMsg2).contains(parameters)) {

                        setParameter(sourceMsg2, parameters, "to");
                        size_max_input++;
                        // logger.info("size_max_input = " + size_max_input);
                        if (size_max_input > 2) size_max_done = true;
                        break;
                    }
                    */

                    httpSender.sendAndReceive(sourceMsg2);
                    ExtensionHistory extHistory =
                            ((ExtensionHistory)
                                    Control.getSingleton()
                                            .getExtensionLoader()
                                            .getExtension(ExtensionHistory.NAME));
                    // sourceMsg2.setNote("Test avec :" + payload);
                    extHistory.addHistory(sourceMsg2, HistoryReference.TYPE_PROXIED);
                    cookies = sourceMsg2.getCookieParams();
                } catch (DatabaseException | IOException e) {
                    // TODO Auto-generated catch block
                    int _acc = 0;
                    ExtensionHistory extHistory =
                            ((ExtensionHistory)
                                    Control.getSingleton()
                                            .getExtensionLoader()
                                            .getExtension(ExtensionHistory.NAME));
                    // sourceMsg2.setNote("Test avec :" + payload);
                    extHistory.addHistory(sourceMsg2, HistoryReference.TYPE_PROXIED);
                    size_max_input++;
                    while (_acc < 5) {
                        logger.info("Error : e = " + e.getMessage());
                        logger.info("size_max_input  = " + size_max_input);

                        _acc++;
                        if (size_max_input > 2) size_max_done = true;
                    }
                    e.printStackTrace();
                }
            }
        }
    }

    @Override
    public boolean isFinish() {
        // TODO Auto-generated method stub
        return false;
    }
}
