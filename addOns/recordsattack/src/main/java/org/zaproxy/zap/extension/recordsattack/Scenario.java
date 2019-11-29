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

import org.parosproxy.paros.network.HttpMessage;

public class Scenario {
    private String name;
    private String comments;

    Scenario(String name, String comments) {
        this.name = name;
        this.comments = comments;
    }

    public void replayScenario() {}

    public void sendRequest(HttpMessage message, String param, String payload) {

        Injection injection = new Injection();
        injection.scan(message, param, payload);
    }
}
