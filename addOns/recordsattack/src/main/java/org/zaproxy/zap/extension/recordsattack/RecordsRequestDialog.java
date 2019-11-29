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

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.view.MainFrame;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class RecordsRequestDialog extends StandardFieldsDialog {

    protected static final String[] LABELS = {
        "spiderajax.scandialog.tab.scope",
        /*"spiderajax.scandialog.tab.elements"*/ };

    private static final String FIELD_SCENARIO = "recordsattack.scandialog.label.scenario";
    private static final String FIELD_AUTHENTIFICATION =
            "recordsattack.scandialog.label.authentification";
    private static final String FIELD_USER = "spiderajax.scandialog.label.user";
    private static final String FIELD_IN_SCOPE = "spiderajax.scandialog.label.inscope";
    private static final String FIELD_SUBTREE_ONLY =
            "spiderajax.scandialog.label.spiderSubtreeOnly";
    private static final String FIELD_BROWSER = "spiderajax.scandialog.label.browser";
    private static final String FIELD_ADVANCED = "spiderajax.scandialog.label.adv";

    private static final String FIELD_NUM_BROWSERS = "spiderajax.options.label.browsers";

    private static final String FIELD_DEPTH = "spiderajax.options.label.depth";
    private static final String FIELD_CRAWL_STATES = "spiderajax.options.label.crawlstates";
    private static final String FIELD_DURATION = "spiderajax.options.label.maxduration";
    private static final String FIELD_EVENT_WAIT = "spiderajax.options.label.eventwait";
    private static final String FIELD_RELOAD_WAIT = "spiderajax.options.label.reloadwait";

    private static final Logger logger = Logger.getLogger(RecordsRequestDialog.class);

    private static final long serialVersionUID = 1L;

    private ExtensionRecordsAttack extension = null;

    private final ExtensionUserManagement extUserMgmt;

    public RecordsRequestDialog(ExtensionRecordsAttack ext, MainFrame owner, Dimension dim) {
        super(owner, "requestRecords.scandialog.title", dim, LABELS);
        this.extension = ext;
        this.extUserMgmt =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionUserManagement.class);
    }

    public void init() {
        logger.debug("init ");

        this.removeAllFields();
        this.addTextField(0, FIELD_SCENARIO, "Scenario");
        this.addComboField(0, FIELD_AUTHENTIFICATION, new String[] {}, "");
        this.addFieldListener(
                FIELD_AUTHENTIFICATION,
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        // @TODO
                        // setUsers();
                    }
                });

        this.pack();
    }

    @Override
    public void save() {
        this.extension.startRecord();
    }

    @Override
    public String validateFields() {
        logger.info(" IL A APPUYER SUR SAVE !! ");
        return null;
    }

    @Override
    public String getHelpIndex() {
        return "addon.spiderajax.dialog";
    }

    @Override
    public String getSaveButtonText() {
        return Constant.messages.getString("spiderajax.scandialog.button.scan");
    }
}
