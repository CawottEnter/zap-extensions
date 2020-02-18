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
package org.zaproxy.zap.extension.recordsattack;

import java.util.HashSet;
import java.util.Observable;
import java.util.Observer;
import java.util.Set;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;

public class ProxySeleniumListener extends Observable implements ProxyListener {
    private static final Logger logger = Logger.getLogger(ProxySeleniumListener.class);
    private Boolean intercept = false;
    private final Session session;
    private ExtensionRecordsAttack extension;

    private Set<Observer> observers = new HashSet<>();

    ProxySeleniumListener(ExtensionRecordsAttack extension) {
        super();
        this.extension = extension;
        this.session = extension.getModel().getSession();
    }

    public void addObserver(Observer observer) {
        observers.add(observer);
    }

    public void removeObserver(Observer observer) {
        observers.remove(observer);
    }

    @Override
    public int getArrangeableListenerOrder() {
        return 0;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        if (intercept) {

            try {
                if (this.extension
                        .getContext()
                        .isIncluded(msg.getRequestHeader().getURI().getURI())) {
                    logger.info("ProxySeleniumListener request send");

                    msg.setNote("ploufa");
                    logger.info("_debug  " + msg.getHttpSession());
                    notifyObservers(msg, true);
                    logger.info("Sortie de onHttpRequest");
                }

            } catch (URIException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        return true;
    }

    public void notifyObservers(HttpMessage message, boolean send) {
        this.observers.stream().forEach(t -> t.update(this, message));
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {

        if (intercept) {

            try {
                if (this.extension
                        .getContext()
                        .isIncluded(msg.getRequestHeader().getURI().getURI())) {
                    logger.info("ProxySeleniumListener request itnercept");

                    // msg.setNote("plouf");
                    logger.info("_debug  " + msg.getHttpSession());
                    notifyObservers(msg, false);
                }

            } catch (URIException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        return true;
    }

    public void startIntercept() {
        intercept = true;
    }

    public void stopIntercept() {
        intercept = false;
    }
}
