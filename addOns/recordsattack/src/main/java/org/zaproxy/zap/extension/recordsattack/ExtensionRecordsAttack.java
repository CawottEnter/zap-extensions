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

import java.awt.Toolkit;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.KeyStroke;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionRecordsAttack extends ExtensionAdaptor {

    private static final Logger logger = Logger.getLogger(ExtensionRecordsAttack.class);
    public static final int PROXY_LISTENER_ORDER = ProxyListenerLog.PROXY_LISTENER_ORDER + 1;
    public static final String NAME = "ExtensionRecordsAttack";
    private SpiderListener spiderListener;
    private boolean recordsRunning;

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionSelenium.class);

        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    private RecordsPanel recordsPanel = null;
    private RecordsRequestDialog recordsDialog = null;
    private RecordsAttackAPI recordsAttackApi;
    private ZapMenuItem menuItemCustomScan;

    /**
     * initializes the extension
     *
     * @throws ClassNotFoundException
     */
    public ExtensionRecordsAttack() throws ClassNotFoundException {
        super(NAME);
        this.setI18nPrefix("recordsattack");
        this.setOrder(234);
    }

    @Override
    public void init() {
        super.init();
        recordsAttackApi = new RecordsAttackAPI(this);
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
        logger.info("Extension Records hooking");
        super.hook(extensionHook);
        extensionHook.addApiImplementor(recordsAttackApi);

        if (getView() != null) {
            extensionHook.getHookView().addStatusPanel(getRecordsPanel());
            extensionHook.getHookMenu().addToolsMenuItem(getMenuItemCustomScan());
        }
    }

    @SuppressWarnings("deprecation")
    private ZapMenuItem getMenuItemCustomScan() {
        if (menuItemCustomScan == null) {
            menuItemCustomScan =
                    new ZapMenuItem(
                            "recordsattack.menu.tools.label",
                            KeyStroke.getKeyStroke(
                                    KeyEvent.VK_X,
                                    // TODO Use getMenuShortcutKeyMaskEx() (and remove warn
                                    // suppression) when targeting Java 10+
                                    Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()
                                            | KeyEvent.ALT_DOWN_MASK,
                                    false));
            menuItemCustomScan.setEnabled(Control.getSingleton().getMode() != Mode.safe);

            menuItemCustomScan.addActionListener(
                    new java.awt.event.ActionListener() {

                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            showScanDialog(null);
                        }
                    });
        }
        return menuItemCustomScan;
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
            recordsPanel.setName(this.getMessages().getString("recordsattack.panel.title"));
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

    RecordThread createSpiderThread(SpiderListener listener) {
        RecordThread recordThread = new RecordThread(this, listener);
        return recordThread;
    }

    public boolean isRecordRunning() {
        return recordsRunning;
    }

    private void setRecordRunning(boolean running) {
        recordsRunning = running;
    }

    /**
     * Starts a new spider scan, with the given display name and using the given target.
     *
     * <p><strong>Note:</strong> The preferred method to start the scan is with {@link
     * #startScan(AjaxSpiderTarget)}, unless a custom display name is really needed.
     *
     * @param displayName the name of the scan (to be displayed in UI)
     * @param listener a listener that will be notified of the scan progress
     * @throws IllegalStateException if the target is not allowed in the current {@link
     *     org.parosproxy.paros.control.Control.Mode mode}.
     */
    @SuppressWarnings("fallthrough")
    public void startRecord(String displayName, SpiderListener listener) {
        if (getView() != null) {
            switch (Control.getSingleton().getMode()) {
                case safe:
                case protect:
                case standard:
                case attack:
                default:
                    // No problem
                    break;
            }

            getRecordsPanel().startRecord(displayName, listener);
        }
    }
}
