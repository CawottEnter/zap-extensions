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
import java.awt.Point;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
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
    protected static final String[] LABELS = {"SAVE", "PARAMETERS","URLS"};

    private static final String FIELD_NAME = "recordsattack.savedialog.label.name";
    private static final String FIELD_DESCRIPTION = "recordsattack.savedialog.label.description";

    /** */
    private static final long serialVersionUID = 1L;

    private ParametersTableModel modelParametersSelected = null;
    private ParametersTableModel modelParametersNotSelected = null;
    private JTable tableParametersSelected = null;
    private JTable tableParametersNotSelected = null;
    private List<WrapperParameter> listParameters = null;

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

        String headers[] = {"Name", "Value", "Count", "Type"};
        String values[][] = {};

        modelParametersSelected = new ParametersTableModel(values, headers);
        modelParametersNotSelected = new ParametersTableModel(values, headers);

        tableParametersSelected = new JTable(modelParametersSelected);
        tableParametersNotSelected = new JTable(modelParametersNotSelected);
        tableParametersSelected.setAutoCreateRowSorter(true);
        tableParametersNotSelected.setAutoCreateRowSorter(true);

        JScrollPane scrollPane = new JScrollPane(tableParametersSelected);
        JScrollPane scrollPane2 = new JScrollPane(tableParametersNotSelected);
        JPanel panel = new JPanel();
        JPanel panel2 = new JPanel();
        panel.add(scrollPane);
        panel2.add(scrollPane2);
        JSplitPane splitting = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, panel, panel2);

        tableParametersSelected.addMouseListener(
                new MouseAdapter() {
                    public void mousePressed(MouseEvent mouseEvent) {
                        JTable table = (JTable) mouseEvent.getSource();
                        Point point = mouseEvent.getPoint();
                        int row = table.rowAtPoint(point);
                        if (mouseEvent.getClickCount() == 2 && table.getSelectedRow() != -1) {
                            logger.info("ID r�cup�rer : " + table.getSelectedRow());
                            Object[] rowToOtherTable =
                                    modelParametersSelected.removeRow(table.getSelectedRow());
                            modelParametersNotSelected.addRow(rowToOtherTable);
                        }
                    }
                });
        
        
        java.util.List<AjaxSpiderTableEntry> cloneHistory =
                new ArrayList<AjaxSpiderTableEntry>(
                        this.extension
                                .getRecordsPanel()
                                .getRecordsAttackResultsTableModel()
                                .getResources());

        fillTable(cloneHistory);

        for (WrapperParameter parameter : listParameters) {
            List<String[]> list = new ArrayList<String[]>();
            list.add(
                    new String[] {
                        parameter.getName(),
                        parameter.getValue(),
                        String.valueOf(parameter.getUsed()),
                        parameter.getMethod()
                    });
            Object[][] data2 = list.toArray(new String[0][0]);
            modelParametersSelected.setData(data2);
        }
        // super.tabOffsets.get(1);
        // this.addField(this.tabPanels.get(1), this.tabOffsets.get(1), "toito",
        // splitting,splitting,0.0D);
        this.addPadding(0);

        this.addTextField(0, FIELD_NAME, "Description");
        this.addTextField(0, FIELD_DESCRIPTION, "Description");
        // this.addTableField(1, toto);
        this.add(splitting, 1);

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

    private Map<String[], String> getParameter(HistoryReference reference) {
        Map<String[], String> map = new HashMap<String[], String>();
        try {
            map.put(reference.getHttpMessage().getParamNames(), reference.getMethod());
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return map;
    }

    private void fillTable(java.util.List<AjaxSpiderTableEntry> cloneHistory) {
        listParameters = new ArrayList<WrapperParameter>();
        for (AjaxSpiderTableEntry entry : cloneHistory) {
            Map<String[], String> parametersAndMethod = getParameter(entry.getHistoryReference());
            parametersAndMethod.forEach(
                    (k, method) -> {
                        for (String nameParam : k) {
                            /*
                             * TODO in Java 9 remplace them by .map(o -> o.getTime()).orElse(0L);
                             * is more elegent
                             *
                             */

                            Optional<WrapperParameter> maybeItExist =
                                    containsParameter(listParameters, nameParam, method);
                            maybeItExist.ifPresent(
                                    p -> {
                                        p.incrementValue();
                                    });
                            if (!maybeItExist.isPresent()) {
                                listParameters.add(
                                        new WrapperParameter(nameParam, "toto", 1, method));
                            }
                        }
                    });
        }
    }

    private Optional<WrapperParameter> containsParameter(
            List<WrapperParameter> listParameters, String param, String method) {
        logger.info("Param to print : " + param);
        logger.info("method = " + method);
        return listParameters.stream()
                .filter(
                        o ->
                                o.getName().equals(param)
                                        && o.getMethod() != null
                                        && o.getMethod().equals(method))
                .findFirst();
    }
}

class WrapperParameter {
    private String parameters;
    private String value;
    private int used;
    private String method;

    WrapperParameter(String parameters, String value, int used, String method) {
        this.parameters = parameters;
        this.setValue(value);
        this.used = used;
        this.method = method;
    }

    public void incrementValue() {
        this.used++;
    }

    @Override
    public boolean equals(Object parameterName) {
        /*
         * if(parameterName instanceof String) { String parameterNameStr =
         * (String)parameterName; if (parameterNameStr.equals(parameterName)) return
         * true; } return false;
         */
        return true;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public int getUsed() {

        return used;
    }

    public String getName() {

        return parameters;
    }

    /** Dummy override */
    @Override
    public int hashCode() {
        return parameters.hashCode();
    }

    public String getMethod() {

        return method;
    }

    static class ParametersSortingByUsedComparator implements Comparator<WrapperParameter> {

        @Override
        public int compare(WrapperParameter parameter1, WrapperParameter parameter2) {
            return parameter1.getUsed() - parameter2.getUsed();
        }
    }
}
