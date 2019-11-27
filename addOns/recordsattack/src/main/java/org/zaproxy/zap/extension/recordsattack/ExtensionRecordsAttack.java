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
import java.util.Collections;
import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.utils.DisplayUtils;

public class ExtensionRecordsAttack extends ExtensionAdaptor {

    private static final Logger logger = Logger.getLogger(ExtensionRecordsAttack.class);
    public static final int PROXY_LISTENER_ORDER = ProxyListenerLog.PROXY_LISTENER_ORDER + 1;
    public static final String NAME = "ExtensionRecordsAttack";
    private ProxyRecordsListener proxyListener;

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionSelenium.class);

        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    private RecordsPanel recordsPanel = null;
    private RecordsRequestDialog recordsDialog = null;

    /**
     * initializes the extension
     *
     * @throws ClassNotFoundException
     */
    public ExtensionRecordsAttack() throws ClassNotFoundException {
        super(NAME);
        this.setI18nPrefix("recordsAttack");
        this.setOrder(234);
    }

    @Override
    public void init() {
        super.init();
    }

    @Override
    public String getAuthor() {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * starts the proxy and all elements of the UI
     *
     * @param extensionHook the extension
     */
    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        if (getView() != null) {
            extensionHook.getHookView().addStatusPanel(getRecordsPanel());
            extensionHook.addProxyListener(getProxyListener());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    /**
     * Creates the panel with the config of the proxy
     *
     * @return the panel
     */
    protected RecordsPanel getRecordsPanel() {
        if (recordsPanel == null) {
            recordsPanel = new RecordsPanel(this);
            recordsPanel.setName(this.getMessages().getString("requestRecords.panel.title"));
        }
        return recordsPanel;
    }

    public void showScanDialog(SiteNode node) {
        if (recordsDialog == null) {
            recordsDialog =
                    new RecordsRequestDialog(
                            this,
                            View.getSingleton().getMainFrame(),
                            DisplayUtils.getScaledDimension(700, 500));
            recordsDialog.init();
        }
        recordsDialog.setVisible(true);
    }

    public ProxyListener getProxyListener() {
        if (proxyListener == null) {
            proxyListener = new ProxyRecordsListener();
        }
        return proxyListener;
    }
    

    public void setProxyListener(ProxyRecordsListener proxyListener) {
        this.proxyListener = proxyListener;
    }
}
