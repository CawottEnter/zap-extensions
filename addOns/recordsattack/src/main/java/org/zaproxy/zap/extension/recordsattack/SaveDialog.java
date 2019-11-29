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
import javax.swing.JSplitPane;
import javax.swing.JTable;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.view.MainFrame;
import org.zaproxy.zap.extension.recordsattack.RecordsAttackResultsTableModel.AjaxSpiderTableEntry;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class SaveDialog extends StandardFieldsDialog {
    private static final Logger logger = Logger.getLogger(StandardFieldsDialog.class);

    private ExtensionRecordsAttack extension;
    private ExtensionUserManagement extUserMgmt;
    protected static final String[] LABELS = {"SAVE", "PARAMETERS"};

    private static final String FIELD_NAME = "recordsattack.savedialog.label.name";
    private static final String FIELD_DESCRIPTION = "recordsattack.savedialog.label.description";

    /** */
    private static final long serialVersionUID = 1L;

    public SaveDialog(ExtensionRecordsAttack ext, MainFrame owner, Dimension dim) {
        super(owner, "requestrecords.scandialog.save.title", dim, LABELS);
        this.extension = ext;
        this.extUserMgmt =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionUserManagement.class);
    }

    public void init() {
        logger.debug("init ");
        this.removeAllFields();
        String[] columnNames = {"First Name", "Last Name", "Sport", "# of Years", "Vegetarian"};
        Object[][] data = {
            {"Kathy", "Smith", "Snowboarding", new Integer(5), new Boolean(false)},
            {"John", "Doe", "Rowing", new Integer(3), new Boolean(true)},
            {"Sue", "Black", "Knitting", new Integer(2), new Boolean(false)},
            {"Jane", "White", "Speed reading", new Integer(20), new Boolean(true)},
            {"Joe", "Brown", "Pool", new Integer(10), new Boolean(false)}
        };
        JTable toto = new JTable(data, columnNames);
        toto.createDefaultColumnsFromModel();
        JTable toto2 = new JTable(new ParametersTableModel());
        JSplitPane splitting = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, toto, toto2);
        // super.tabOffsets.get(1);
        // this.addField(this.tabPanels.get(1), this.tabOffsets.get(1), "toito",
        // splitting,splitting,0.0D);
        this.addPadding(0);

        this.addTextField(0, FIELD_NAME, "Description");
        this.addTextField(0, FIELD_DESCRIPTION, "Description");
        // this.addTableField(1, toto);
        this.add(splitting, 1);

        // this.addTableField(0, field);
        java.util.List<AjaxSpiderTableEntry> cloneHistory =
                new ArrayList<AjaxSpiderTableEntry>(
                        this.extension
                                .getRecordsPanel()
                                .getRecordsAttackResultsTableModel()
                                .getResources());
        for (AjaxSpiderTableEntry entry : cloneHistory) getParameter(entry.getHistoryReference());

        this.setCustomTabPanel(1, splitting);
        this.addPadding(1);

        this.pack();
    }

    @Override
    public void save() {
        // TODO Auto-generated method stub

    }

    @Override
    public String validateFields() {
        // TODO Auto-generated method stub
        return null;
    }

    private ArrayList<String> getParameter(HistoryReference reference) {
        String[] params;
        try {
            params = reference.getHttpMessage().getParamNames();
            for (String p : params) logger.info("PARAMETER FOUND : " + p);
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        ArrayList<String> parameters = new ArrayList<String>();
        return parameters;
    }
}
