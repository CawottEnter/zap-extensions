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
package org.zaproxy.zap.extension.seleniumrectorat;

import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class ProxyListener implements org.parosproxy.paros.core.proxy.ProxyListener {
    private static final Logger logger = Logger.getLogger(ProxyListener.class);
    private Boolean record = false;
    private Boolean attack = false;
    private ExtensionSeleniumRectorat extension;
    private Session session;
    private List<String> parameters;
    private List<HistoryReference> historyReferenceList;
    private Scanner scanner;

    ProxyListener(ExtensionSeleniumRectorat extension) {
        this.extension = extension;
        this.session = extension.getModel().getSession();
        parameters = new ArrayList<>();
        scanner = new Scanner();
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        if (record) {
            if (this.extension
                    .getContext()
                    .isIncluded(msg.getRequestHeader().getURI().toString())) {
                /*
                On va recuperer la requête et verifier si un parametre contient la valeur d'attaque "THIS"
                 */
                try {
                    scanner = new Scanner();
                    parameters.addAll(scanner.searchValueInRequest(msg, "THIS"));
                    HistoryReference historyRef = new HistoryReference(this.session, 50, msg);
                    historyReferenceList.add(historyRef);
                } catch (HttpMalformedHeaderException e) {
                    e.printStackTrace();
                } catch (DatabaseException e) {
                    e.printStackTrace();
                }
            }
        } else if (attack) {

            if (this.extension
                    .getContext()
                    .isIncluded(msg.getRequestHeader().getURI().toString())) {
                scanner.setParameter(msg, "user", "AA");
            }

            /*
            if (msg.getRequestHeader().getMethod().equals("POST"))
                msg.getRequestBody().append("&toto=");

             */

        }
        return true;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
        return true;
    }

    @Override
    public int getArrangeableListenerOrder() {
        return 0;
    }

    public Boolean getRecord() {
        return record;
    }

    public void startRecord() {
        historyReferenceList = new ArrayList<>();
        record = true;
    }

    public void stopRecord() {
        record = false;
    }

    public void startAttack() {
        attack = true;
    }

    public void stopAttack() {
        attack = false;
    }

    public List<String> getParameters() {
        return this.parameters;
    }
}
