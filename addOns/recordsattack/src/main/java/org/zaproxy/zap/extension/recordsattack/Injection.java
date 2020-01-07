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
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.core.scanner.Scanner;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.extension.recordsattack.refound.BufferOverflow;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class Injection {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "extension.recordsattack.";

    private static final String[] PARAM_ATTACK_STRINGS = {"toto", "tat"};
    private HttpSender httpSender;
    private static final int PLUGIN_ID = 7610110;
    private static Logger log = Logger.getLogger(Injection.class);
    private List<String> paramsTarget;

    // protected HostProcess parent;

    // protected ScannerParam scannerParam;

    public void scan(HttpMessage msg, String param, String value) {

        // goes through all checks and stops if it finds a possible

        String payload = "toto";
        tryInjection(msg, param, payload);


    }

    private void tryInjection(HttpMessage msg, String paramName, String payload) {
        BufferOverflow activeScanBufferOverflow = new BufferOverflow();
        msg = msg.cloneRequest();
        activeScanBufferOverflow.scan(msg, paramName, "toto");
        log.info("AFTER new url :" + msg.getRequestHeader().getURI());
        log.info("AFTER new url :" + msg.getRequestHeader().getURI());
        log.info("AFTER new url :" + msg.getRequestHeader().getURI());
        log.info("AFTER new url :" + msg.getRequestHeader().getURI());

        HttpSender httpSender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(), true, 101);
        try {
            httpSender.sendAndReceive(msg);
        } catch (IOException e) {
            log.info("Erreur : e = " + e.getMessage());
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        ExtensionHistory extHistory =
                ((ExtensionHistory)
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionHistory.NAME));
        extHistory.addHistory(msg, HistoryReference.TYPE_PROXIED);
    }
    /*
     * catch (Exception e) { log.error(e.getMessage(), e); }
     */

}
