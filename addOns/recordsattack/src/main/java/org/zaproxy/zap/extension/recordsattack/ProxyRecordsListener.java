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

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.network.HttpMessage;

public class ProxyRecordsListener implements ProxyListener {
    private static final Logger logger = Logger.getLogger(ProxyRecordsListener.class);
    private List<HttpMessage> requestMsg;
    private List<HttpMessage> receiveMsg;
    private Boolean record = false;

    @Override
    public int getArrangeableListenerOrder() {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
    	if (record)  {
        logger.debug("ProxyRecordsListener request this msg : " + msg);
        logger.debug(msg.getRequestHeader());
    	}
        return true;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
    	if (record) {
        logger.debug("ProxyRecordsListener Receive this msg : " + msg);
        logger.debug(msg.getRequestHeader());
    	}

        return true;
    }
    
    public void runRecord()
    {
    	if (requestMsg == null)
    		requestMsg = new ArrayList<HttpMessage>();
    	if(receiveMsg == null)
    		receiveMsg = new ArrayList<HttpMessage>();
    	record = true;
    	
    }
}
