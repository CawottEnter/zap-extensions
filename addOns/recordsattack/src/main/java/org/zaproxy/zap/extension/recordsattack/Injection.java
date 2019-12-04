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
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;

public class Injection extends PassiveScanner  {

    /** Prefix for internationalised messages used by this rule */

    private static final String MESSAGE_PREFIX = "extension.recordsattack.";
    private static final String[] PARAM_ATTACK_STRINGS = { "toto", "tat" };
    private HttpSender httpSender;
    private static final int PLUGIN_ID = 7610110;
    private static Logger log = Logger.getLogger(Injection.class);




    @Override
    public void scan(HttpMessage msg, String param, String value) {

	// goes through all checks and stops if it finds a possible

	// injection
	String payload = "toto";
	tryInjection(msg, param, payload);
    }

    private void tryInjection(HttpMessage msg, String paramName, String payload) {
	httpSender =
		scanHttpRequestSend
                new HttpSender(

                        Model.getSingleton().getOptionsParam().getConnectionParam(),

                        true,

                        HttpSender.FUZZER_INITIATOR);
        HttpMessage sourceMsg2 = msg.cloneRequest();
        // setParameter(sourceMsg2, paramName, payload);
        try {
            log.info("Try Injection, paramName =" + paramName);
    	httpSender.sendAndReceive(msg);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    @Override

    public int getRisk() {

	return Alert.RISK_HIGH;

    }

    @Override

    public int getCweId() {

	return 89;

    }

    @Override

    public int getWascId() {

	return 19;

    }
}
