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
import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.view.MainFrame;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class AuthentificationDialog extends StandardFieldsDialog {
    /** */
    private static final long serialVersionUID = 4925094056489672384L;

    private ExtensionRecordsAttack extension;
    private ExtensionUserManagement extUserMgmt;
    protected static final String[] LABELS = {"spiderajax.scandialog.tab.scope"};
    private static final String FIELD_NAME = "recordsattack.savedialog.label.name";
    private static final String FIELD_DESCRIPTION = "recordsattack.savedialog.label.description";

    public AuthentificationDialog(ExtensionRecordsAttack ext, MainFrame owner, Dimension dim) {
        super(owner, "requestrecords.scandialog.save.title", dim, LABELS);
        this.extension = ext;
        this.extUserMgmt =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionUserManagement.class);
    }

    public void init() {

        this.addTextField(0, FIELD_NAME, "Name authentification");
        this.addTextField(0, FIELD_DESCRIPTION, "Description");
    }

    @Override
    public void save() {
        String nameAuthentification = this.getStringValue(FIELD_NAME);
        String descriptionAuthentification = this.getStringValue(FIELD_DESCRIPTION);
        List<HistoryReference> references = new ArrayList<HistoryReference>();
        this.extension
                .getRecordsPanel()
                .getRecordsAttackResultsTableModel()
                .getResources()
                .forEach(
                        ress -> {
                            references.add(ress.getHistoryReference());
                        });

        Authentification authentification =
                new Authentification(nameAuthentification, descriptionAuthentification, references);
        this.extension.getAuthentification().add(authentification);
        this.extension.getRecordsPanel().getRecordsAttackResultsTableModel().clear();
    }

    @Override
    public String validateFields() {
        // TODO Auto-generated method stub
        return null;
    }
}
