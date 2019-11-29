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

import java.io.IOException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

public class Injection extends AbstractAppParamPlugin {
    private static final String MESSAGE_PREFIX = "ascanalpha.recordsattack.";

    @Override
    public int getId() {
        return 7610110;
    }

    @Override
    public String getName() {

        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {

        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {

        // goes through all checks and stops if it finds a possible

        // injection
        String payload = "toto";
        tryInjection(msg, param, payload);
    }

    private void tryInjection(HttpMessage msg, String param, String payload) {
        try {
            msg = sendRequest(msg, param, payload);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private HttpMessage sendRequest(HttpMessage msg, String param, String value)
            throws IOException {
        msg = getNewMsg();
        setParameter(msg, param, value);
        sendAndReceive(msg);
        return msg;
    }
}
