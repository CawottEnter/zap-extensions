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
package org.zaproxy.zap.extension.recordsattack;

import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class Scenario {
    private static final Logger logger = Logger.getLogger(Scenario.class);
    private String name;
    private String comments;
    private List<String> params;
    private List<HistoryReference> historyReference;

    Scenario(
            String name,
            String comments,
            List<String> paramsSelected,
            List<HistoryReference> references) {
        this.name = name;
        this.comments = comments;
        this.params = paramsSelected;
        this.historyReference = references;
    }

    public void replayScenario() {
        for (String p : params) {
            logger.info("attack on p : " + p);
            for (HistoryReference reference : historyReference) {
                try {
                    logger.info("reference id : " + reference.getHistoryId());
                    HttpMessage message = reference.getHttpMessage();
                    String payload = "toto";
                    sendRequest(message, p, payload);
                } catch (HttpMalformedHeaderException | DatabaseException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }
    }

    public void sendRequest(HttpMessage message, String param, String payload) {

        Injection injection = new Injection();
        injection.scan(message, param, payload);
    }
}
