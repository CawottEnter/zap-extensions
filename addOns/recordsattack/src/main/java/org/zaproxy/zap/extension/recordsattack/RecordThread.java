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

import java.awt.EventQueue;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;

public class RecordThread implements Runnable {
    private static final Logger logger = Logger.getLogger(RecordThread.class);
    private boolean running;
    private final ExtensionRecordsAttack extension;
    private List<SpiderListener> spiderListeners;

    RecordThread(ExtensionRecordsAttack extension, SpiderListener spiderListener) {
        this.extension = extension;
        this.running = false;
        spiderListeners = new ArrayList<>(2);
        spiderListeners.add(spiderListener);
    }

    @Override
    public void run() {
        // TODO Auto-generated method stub

    }

    /** @return the RecordThread object */
    public RecordThread getRecordThread() {
        return this;
    }
    /** @return the SpiderThread object */
    public boolean isRunning() {
        return this.running;
    }

    private void notifySpiderListenersFoundMessage(
            HistoryReference historyReference,
            HttpMessage httpMessage,
            org.zaproxy.zap.extension.recordsattack.SpiderListener.ResourceState state) {
        for (SpiderListener listener : spiderListeners) {
            listener.foundMessage(historyReference, httpMessage, state);
        }
    }

    private void notifyMessage(
            final HttpMessage httpMessage,
            final int historyType,
            final org.zaproxy.zap.extension.recordsattack.SpiderListener.ResourceState state) {
        try {
            if (extension.getView() != null && !EventQueue.isDispatchThread()) {
                EventQueue.invokeLater(
                        new Runnable() {

                            @Override
                            public void run() {
                                notifyMessage(httpMessage, historyType, state);
                            }
                        });
                return;
            }

            HistoryReference historyRef = new HistoryReference(null, historyType, httpMessage);
            if (state
                    == org.zaproxy.zap.extension.recordsattack.SpiderListener.ResourceState
                            .PROCESSED) {
                historyRef.setCustomIcon("/resource/icon/10/spiderAjax.png", true);
            }

            notifySpiderListenersFoundMessage(historyRef, httpMessage, state);
        } catch (Exception e) {
            logger.error(e);
        }
    }

    public class ProxyRecordsListener implements ProxyListener {
        private List<HttpMessage> requestMsg;
        private List<HttpMessage> receiveMsg;
        private Boolean record = false;

        @Override
        public int getArrangeableListenerOrder() {
            return 0;
        }

        @Override
        public boolean onHttpRequestSend(HttpMessage msg) {
            return true;
        }

        @Override
        public boolean onHttpResponseReceive(HttpMessage msg) {
            notifyMessage(msg, HistoryReference.TYPE_SPIDER_AJAX, getResourceState(msg));

            return true;
        }

        public void runRecord() {
            if (requestMsg == null) requestMsg = new ArrayList<HttpMessage>();
            if (receiveMsg == null) receiveMsg = new ArrayList<HttpMessage>();
            record = true;
        }

        private org.zaproxy.zap.extension.recordsattack.SpiderListener.ResourceState
                getResourceState(HttpMessage httpMessage) {
            if (!httpMessage.isResponseFromTargetHost()) {
                return org.zaproxy.zap.extension.recordsattack.SpiderListener.ResourceState
                        .IO_ERROR;
            }
            return org.zaproxy.zap.extension.recordsattack.SpiderListener.ResourceState.PROCESSED;
        }
    }

    public void addSpiderListener(SpiderListener listener) {
        spiderListeners.add(listener);
    }
}
