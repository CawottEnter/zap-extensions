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
package org.zaproxy.zap.extension.seleniumrectorat;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.model.Context;

public class ExtensionSeleniumRectorat extends ExtensionAdaptor {

    private static final Logger logger = Logger.getLogger(ExtensionSeleniumRectorat.class);
    public static final String NAME = "Selenium Rectorat";

    private static final List<Class<? extends Extension>> DEPENDENCIES;
    private Context context;
    private SeleniumRectoratAPI seleniumRectoratAPI;
    /*The proxy listener*/
    private ProxyListener proxyListener;

    private Boolean authentificationRecord = false;
    private Boolean attackMode = false;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionSelenium.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    //  private RecordsPanel recordsPanel = null;

    /**
     * initializes the extension
     *
     * @throws ClassNotFoundException
     */
    public ExtensionSeleniumRectorat() throws ClassNotFoundException {
        super(NAME);
        this.setI18nPrefix("seleniumrectorat");
        this.setOrder(234);
    }

    @Override
    public void init() {
        super.init();
        seleniumRectoratAPI = new SeleniumRectoratAPI(this);
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
            extensionHook.addApiImplementor(seleniumRectoratAPI);
            extensionHook.addProxyListener(getProxyListener());
            /*
            extensionHook.getHookView().addStatusPanel(getRecordsPanel());
            // extensionHook.getHookMenu().addToolsMenuItem(getMenuItemCustomScan());



            extensionHook.addProxyListener(getProxySeleniumListener());

             */
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    public ProxyListener getProxyListener() {
        if (proxyListener == null) {
            proxyListener = new ProxyListener(this);
        }
        return proxyListener;
    }

    public Context getContext() {
        return context;
    }

    public void setContext(Context context) {
        this.context = context;
    }

    public void startAuthentification() {
        authentificationRecord = true;
        getProxyListener().startRecord();
    }

    public void stopAuthentification() {
        authentificationRecord = false;
        getProxyListener().stopRecord();
    }

    public Boolean getAuthentificationRecord() {
        return authentificationRecord;
    }

    public void setAuthentificationRecord(Boolean authentificationRecord) {
        this.authentificationRecord = authentificationRecord;
    }

    public Boolean getAttackMode() {
        return attackMode;
    }

    public void setAttackMode(Boolean attackMode) {
        this.attackMode = attackMode;
    }

    public void startAttack() {
        attackMode = true;
        this.getProxyListener().startAttack();
    }

    public void stopAttack() {
        attackMode = false;
        this.getProxyListener().stopAttack();
    }
}
