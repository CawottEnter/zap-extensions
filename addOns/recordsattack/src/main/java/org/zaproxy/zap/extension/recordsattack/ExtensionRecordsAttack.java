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
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.recordsattack.scenarioModel.TreeScenarioDialog;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.DisplayUtils;

public class ExtensionRecordsAttack extends ExtensionAdaptor {

    private static final Logger logger = Logger.getLogger(ExtensionRecordsAttack.class);
    public static final int PROXY_LISTENER_ORDER = ProxyListenerLog.PROXY_LISTENER_ORDER + 1;
    public static final String NAME = "ExtensionRecordsAttack";
    private ProxyRecordsListener proxyRecordsListener;
    private ProxySeleniumListener proxySeleniumListener;
    private boolean recordsRunning;
    private static final List<Authentification> authentificationsList =
            new ArrayList<Authentification>();

    private static final List<Class<? extends Extension>> DEPENDENCIES;
    private Context context;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionSelenium.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    private RecordsPanel recordsPanel = null;

    private SaveDialog saveDialog = null;
    private AuthentificationDialog authentificationDialog = null;
    private TreeScenarioDialog scenarioDialog = null;
    private List<Scenario> scenarios = null;

    private RecordsAttackAPI recordsAttackAPI;

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
        recordsAttackAPI = new RecordsAttackAPI(this);
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

        if (getView() != null) {
            extensionHook.getHookView().addStatusPanel(getRecordsPanel());
            // extensionHook.getHookMenu().addToolsMenuItem(getMenuItemCustomScan());
            extensionHook.addApiImplementor(recordsAttackAPI);

            extensionHook.addProxyListener(getProxyRecordsListener());
            extensionHook.addProxyListener(getProxySeleniumListener());
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
            recordsPanel.setName(this.getMessages().getString("recordsattack.panel.title"));
        }
        return recordsPanel;
    }

    public void showSaveDialog(SiteNode node) {
        if (saveDialog == null) {
            saveDialog =
                    new SaveDialog(
                            this,
                            View.getSingleton().getMainFrame(),
                            DisplayUtils.getScaledDimension(700, 500));
            saveDialog.init();
        }

        saveDialog.setVisible(true);
    }

    public void showAuthentificationDialog(SiteNode node) {

        if (authentificationDialog == null) {
            authentificationDialog =
                    new AuthentificationDialog(
                            this,
                            View.getSingleton().getMainFrame(),
                            DisplayUtils.getScaledDimension(700, 500));
            authentificationDialog.init();
        }
        authentificationDialog.setVisible(true);
    }

    public void showScenarioDialog(SiteNode node) {
        logger.info("Show scenarios windows");
        if (scenarioDialog == null) {
            scenarioDialog =
                    new TreeScenarioDialog(
                            this,
                            View.getSingleton().getMainFrame(),
                            DisplayUtils.getScaledDimension(700, 500));
        }
        logger.info("Init of scenario Dialog");
        logger.info("_debug scenario in extension is null ? " + (getScenarios() == null));
        scenarioDialog.initialize();
        scenarioDialog.setVisible(true);
    }

    public AuthentificationDialog getAuthentificationDialog() {
        return authentificationDialog;
    }

    public ProxyRecordsListener getProxyRecordsListener() {
        if (proxyRecordsListener == null) {
            proxyRecordsListener = new ProxyRecordsListener(this);
        }
        return proxyRecordsListener;
    }

    /*
     * Start record and modify buttons in pannel
     */
    public void startRecord() {
        recordsPanel.startRecord();
        getProxyRecordsListener().runRecord();
    }

    public List<Authentification> getAuthentification() {
        return authentificationsList;
    }

    public Authentification getAuthentificationById(int id) {
        for (Authentification authentification : getAuthentification())
            if (authentification.getId() == id) return authentification;
        return null;
    }

    public Context getContext() {
        return context;
    }

    public void setContext(Context context) {
        this.context = context;
    }

    public ProxySeleniumListener getProxySeleniumListener() {
        if (proxySeleniumListener == null) proxySeleniumListener = new ProxySeleniumListener(this);

        return proxySeleniumListener;
    }

    public void saveScenario(Scenario scenario) {
        getScenarios().add(scenario);
    }

    public List<Scenario> getScenarios() {
        if (scenarios == null) scenarios = new ArrayList<Scenario>();
        return scenarios;
    }
}
