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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.TreeSet;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.view.MainFrame;
import org.zaproxy.zap.extension.recordsattack.RecordsAttackResultsTableModel.AjaxSpiderTableEntry;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class SaveDialog extends StandardFieldsDialog {
    private static final Logger logger = Logger.getLogger(StandardFieldsDialog.class);

    private ExtensionRecordsAttack extension;
    private ExtensionUserManagement extUserMgmt;
    protected static final String[] LABELS = {"SAVE", "PARAMETERS", "URLS"};

    private static final String FIELD_NAME = "recordsattack.savedialog.label.name";
    private static final String FIELD_DESCRIPTION = "recordsattack.savedialog.label.description";
    private static final String FIELD_AUTHENTIFICATION =
            "recordsattack.savedialog.combofield.authentication";

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

        String headers[] = {"Name", "Value", "Count", "Method", "Type"};
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

        /*
         * URLS parts
         */
        String header2[] = {"value", "OK"};
        ParametersTableModel modelUrls = new ParametersTableModel(values, header2);
        JTable urlTable = new JTable(modelUrls);

        JScrollPane scrollPane3 = new JScrollPane(urlTable);
        JPanel panel3 = new JPanel();
        panel3.add(scrollPane3);

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
        tableParametersNotSelected.addMouseListener(
                new MouseAdapter() {
                    public void mousePressed(MouseEvent mouseEvent) {
                        JTable table = (JTable) mouseEvent.getSource();
                        Point point = mouseEvent.getPoint();
                        int row = table.rowAtPoint(point);
                        if (mouseEvent.getClickCount() == 2 && table.getSelectedRow() != -1) {
                            logger.info("ID r�cup�rer : " + table.getSelectedRow());
                            Object[] rowToOtherTable =
                                    modelParametersNotSelected.removeRow(table.getSelectedRow());
                            modelParametersSelected.addRow(rowToOtherTable);
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
                        parameter.getMethod(),
                        parameter.getType()
                    });
            Object[][] data2 = list.toArray(new String[0][0]);
            modelParametersSelected.setData(data2);
        }
        HashSet<String> urls = getAllUrls(listParameters);
        urls.forEach(
                url -> {
                    Boolean defaultBox = new Boolean(true);

                    Object[] data2 = {url, defaultBox};
                    modelUrls.addRow(data2);
                });

        // super.tabOffsets.get(1);
        // this.addField(this.tabPanels.get(1), this.tabOffsets.get(1), "toito",
        // splitting,splitting,0.0D);
        this.addPadding(0);

        this.addTextField(0, FIELD_NAME, "Description");
        this.addTextField(0, FIELD_DESCRIPTION, "Description");
        List<String> authentifications = new ArrayList<String>();
        this.extension
                .getAuthentification()
                .forEach(
                        authentification -> {
                            authentifications.add(
                                    authentification.getId() + ":" + authentification.getName());
                        });

        this.addComboField(0, FIELD_AUTHENTIFICATION, authentifications, "toto");
        // this.addTableField(1, toto);
        this.add(splitting, 1);

        this.setCustomTabPanel(1, splitting);
        this.addPadding(1);
        this.setCustomTabPanel(2, panel3);
        urlTable.setSize(urlTable.getParent().getSize());

        this.pack();
    }

    public HashSet<String> getAllUrls(List<WrapperParameter> list) {
        HashSet<String> urls = new HashSet<String>();
        list.forEach(
                wrapperParam -> {
                    urls.addAll(wrapperParam.getUrls());
                });
        return urls;
    }

    @Override
    public void save() {
        /*
         * On recupere toutes les
         */
        logger.info("save call :)");
        List<String> paramsSelected = new ArrayList<String>();
        for (int count = 0; count < modelParametersSelected.getRowCount(); count++) {
            paramsSelected.add((String) modelParametersSelected.getValueAt(count, 0));
        }
        logger.info("Parametres selectionner :");
        paramsSelected.forEach(
                s -> {
                    logger.info(s);
                });
        String nameScenario = this.getStringValue(FIELD_NAME);
        String nameDescription = this.getStringValue(FIELD_DESCRIPTION);
        /*
         * We get all informations about this scenario
         */
        logger.info("Name Scenario = " + nameScenario);
        logger.info("Description : " + nameDescription);
        // DefaultMutableTreeNode top = new DefaultMutableTreeNode("The Java Series");

        // org.parosproxy.paros.model.Model.getSingleton().getSession().getSiteTree().setRoot(top);
        List<HistoryReference> references = new ArrayList<HistoryReference>();
        this.extension
                .getRecordsPanel()
                .getRecordsAttackResultsTableModel()
                .getResources()
                .forEach(
                        ress -> {
                            references.add(ress.getHistoryReference());
                        });
        int authId = Integer.valueOf(this.getStringValue(FIELD_AUTHENTIFICATION).split(":")[0]);
        Authentification auth = this.extension.getAuthentificationById(authId);
        Scenario scenario =
                new Scenario(
                        nameScenario,
                        nameDescription,
                        paramsSelected,
                        references,
                        auth,
                        this.extension);
        scenario.replayScenario();
    }

    @Override
    public String validateFields() {
        logger.info("ValidateFields call :)");

        return null;
    }

    private List<WrapperParameter> getParameter(HistoryReference reference) {
        List<WrapperParameter> parameters = new ArrayList<WrapperParameter>();
        String method = reference.getMethod();
        TreeSet<HtmlParameter> set = new TreeSet<>();

        /*
         * We get all parameters
         */

        org.parosproxy.paros.network.HtmlParameter.Type[] typeHtmlParameter = {
            HtmlParameter.Type.form, HtmlParameter.Type.url
        };
        for (org.parosproxy.paros.network.HtmlParameter.Type type : typeHtmlParameter) {
            Map<String, String> paramMap;
            try {
                paramMap =
                        Model.getSingleton()
                                .getSession()
                                .getParams(reference.getHttpMessage(), type);
                for (Entry<String, String> param : paramMap.entrySet()) {
                    set.add(new HtmlParameter(type, param.getKey(), param.getValue()));
                }
                String uri = reference.getURI().getEscapedURI();
                set.forEach(
                        k -> {
                            if (!k.getName().isEmpty())
                                parameters.add(new WrapperParameter(k, method, uri));
                        });

            } catch (HttpMalformedHeaderException | DatabaseException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        return parameters;
    }

    private void fillTable(java.util.List<AjaxSpiderTableEntry> cloneHistory) {
        listParameters = new ArrayList<WrapperParameter>();
        for (AjaxSpiderTableEntry entry : cloneHistory) {
            logger.info("Entry");
            List<WrapperParameter> parametersAndMethod = getParameter(entry.getHistoryReference());
            logger.info("url : " + entry.getUri());
            logger.info("url: " + entry.getHistoryReference().getURI());

            try {
                logger.info(
                        entry.getHistoryReference().getHttpMessage().getParamNames().toString());
            } catch (HttpMalformedHeaderException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (DatabaseException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            parametersAndMethod.forEach(
                    wrapperParameter -> {
                        logger.info("update wrapper : " + wrapperParameter.getName());
                        updateParameters(listParameters, wrapperParameter);
                    });
        }
    }

    private List<WrapperParameter> updateParameters(
            List<WrapperParameter> listParameters, WrapperParameter wp) {
        Optional<WrapperParameter> maybeItExist =
                listParameters.stream()
                        .filter(
                                o ->
                                        o.getName().equals(wp.getName())
                                                && o.getMethod() != null
                                                && o.getMethod().equals(wp.getMethod()))
                        .findFirst();
        maybeItExist.ifPresent(
                p -> {
                    p.incrementValue();
                    p.addUrl(wp.getUrls());
                });
        if (!maybeItExist.isPresent()) {
            listParameters.add(wp);
        }
        return listParameters;
    }
}

class WrapperParameter {
    private HtmlParameter parameter;
    private String method;
    private int used;
    private HashSet<String> urls = new HashSet<String>();
    private boolean hiddenByUrl = false;
    private boolean hidden = false;

    WrapperParameter(HtmlParameter parameters, String method, String url) {
        this.parameter = parameters;
        this.method = method;
        this.used = 1;
        this.urls.add(url);
    }

    public void incrementValue() {
        this.used++;
    }

    public String getType() {

        return this.parameter.getType().toString();
    }

    public HashSet<String> getUrls() {

        return urls;
    }

    public void addUrl(HashSet<String> hashSet) {
        urls.addAll(hashSet);
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
        return parameter.getValue();
    }

    public int getUsed() {

        return used;
    }

    public String getName() {

        return parameter.getName();
    }

    /** Dummy override */
    @Override
    public int hashCode() {
        return parameter.hashCode();
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
