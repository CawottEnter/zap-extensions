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

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.SortedSet;
import java.util.TreeSet;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.KeyStroke;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.ScanStatus;
import org.zaproxy.zap.view.table.HistoryReferencesTable;

public class RecordsPanel extends AbstractPanel implements SpiderListener {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = Logger.getLogger(RecordsPanel.class);

    private javax.swing.JScrollPane scrollLog = null;
    private ExtensionRecordsAttack extension = null;
    private javax.swing.JPanel recordsAttackPanel = null;
    private javax.swing.JToolBar panelToolbar = null;
    private JButton optionsButton = null;

    private JButton startRecordsButton;
    private JButton stopRecordsButton;
    private JButton saveButton;
    private JLabel foundLabel = new JLabel();
    private ScanStatus scanStatus = null;

    private RecordsResultsTable spiderResultsTable;

    private RecordsAttackResultsTableModel spiderResultsTableModel =
            new RecordsAttackResultsTableModel();

    private SortedSet<String> visitedUrls = new TreeSet<>();
    private int foundCount = 0;

    // private RecordsAttackResultsTableModel spiderResultsTableModel =
    // new RecordsAttackResultsTableModel();

    /** This is the default constructor */
    public RecordsPanel(ExtensionRecordsAttack e) {
        super();
        this.extension = e;
        initialize();
    }

    public RecordsAttackResultsTableModel getRecordsAttackResultsTableModel() {

        return spiderResultsTableModel;
    }

    /** This method initializes this class and its attributes */
    @SuppressWarnings("deprecation")
    private void initialize() {
        this.setLayout(new BorderLayout());
        if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
            this.setSize(600, 200);
        }
        this.add(getRecordsAttackPanel(), java.awt.BorderLayout.CENTER);
        scanStatus =
                new ScanStatus(
                        new ImageIcon(
                                RecordsPanel.class.getResource("/resource/icon/16/spiderAjax.png")),
                        this.extension.getMessages().getString("recordsattack.panel.title"));

        this.setDefaultAccelerator(
                KeyStroke.getKeyStroke(
                        // TODO Use getMenuShortcutKeyMaskEx() (and remove warn suppression) when
                        // targeting Java 10+
                        KeyEvent.VK_J,
                        Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()
                                | KeyEvent.SHIFT_DOWN_MASK,
                        false));

        this.setMnemonic(Constant.messages.getChar("spiderajax.panel.mnemonic"));
        if (View.isInitialised()) {
            View.getSingleton()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .addFooterToolbarRightLabel(scanStatus.getCountLabel());
        }
    }

    /** @return the AJAX Spider Panel */
    private javax.swing.JPanel getRecordsAttackPanel() {
        if (recordsAttackPanel == null) {

            recordsAttackPanel = new javax.swing.JPanel();
            recordsAttackPanel.setLayout(new java.awt.GridBagLayout());
            recordsAttackPanel.setName("Spider AJAX Panel");

            GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints2 = new GridBagConstraints();

            gridBagConstraints1.gridx = 0;
            gridBagConstraints1.gridy = 0;
            gridBagConstraints1.weightx = 1.0D;
            gridBagConstraints1.insets = new java.awt.Insets(2, 2, 2, 2);
            gridBagConstraints1.fill = java.awt.GridBagConstraints.HORIZONTAL;
            gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;

            gridBagConstraints2.gridx = 0;
            gridBagConstraints2.gridy = 1;
            gridBagConstraints2.weightx = 1.0;
            gridBagConstraints2.weighty = 1.0;
            gridBagConstraints2.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints2.fill = java.awt.GridBagConstraints.BOTH;
            gridBagConstraints2.anchor = java.awt.GridBagConstraints.NORTHWEST;

            recordsAttackPanel.add(this.getPanelToolbar(), gridBagConstraints1);
            recordsAttackPanel.add(getScrollLog(), gridBagConstraints2);
        }
        return recordsAttackPanel;
    }

    /** @return the panel toolbar */
    private javax.swing.JToolBar getPanelToolbar() {
        if (panelToolbar == null) {
            panelToolbar = new javax.swing.JToolBar();
            panelToolbar.setLayout(new java.awt.GridBagLayout());
            panelToolbar.setEnabled(true);
            panelToolbar.setFloatable(false);
            panelToolbar.setRollover(true);
            panelToolbar.setPreferredSize(new java.awt.Dimension(800, 30));
            panelToolbar.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 12));
            panelToolbar.setName("Spider AJAX Toolbar");
            GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints2 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints3 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints4 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints5 = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsX = new GridBagConstraints();
            GridBagConstraints gridBagConstraints7 = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsy = new GridBagConstraints();

            gridBagConstraints1.gridx = 0;
            gridBagConstraints1.gridy = 0;
            gridBagConstraints1.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints1.anchor = java.awt.GridBagConstraints.WEST;
            gridBagConstraints2.gridx = 1;
            gridBagConstraints2.gridy = 0;
            gridBagConstraints2.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints2.anchor = java.awt.GridBagConstraints.WEST;

            gridBagConstraints3.gridx = 2;
            gridBagConstraints3.gridy = 0;
            gridBagConstraints3.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints3.anchor = java.awt.GridBagConstraints.WEST;

            gridBagConstraints4.gridx = 3;
            gridBagConstraints4.gridy = 0;
            gridBagConstraints4.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints4.anchor = java.awt.GridBagConstraints.WEST;

            gridBagConstraints5.gridx = 4;
            gridBagConstraints5.gridy = 0;
            gridBagConstraints5.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints5.anchor = java.awt.GridBagConstraints.WEST;
            gridBagConstraints7.gridx = 6;
            gridBagConstraints7.gridy = 0;
            gridBagConstraints7.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints7.anchor = java.awt.GridBagConstraints.WEST;
            gridBagConstraintsX.gridx = 5;
            gridBagConstraintsX.gridy = 0;
            gridBagConstraintsX.weightx = 1.0;
            gridBagConstraintsX.weighty = 1.0;
            gridBagConstraintsX.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraintsX.anchor = java.awt.GridBagConstraints.EAST;
            gridBagConstraintsX.fill = java.awt.GridBagConstraints.HORIZONTAL;
            gridBagConstraintsy.gridx = 21;
            gridBagConstraintsy.gridy = 0;
            gridBagConstraintsy.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraintsy.anchor = java.awt.GridBagConstraints.WEST;
            JLabel t1 = new JLabel();

            panelToolbar.add(getStartRecordsButton(), gridBagConstraints1);
            panelToolbar.add(getStopRecordsButton(), gridBagConstraints2);
            panelToolbar.add(getSaveButton(), gridBagConstraints5);

            panelToolbar.add(t1, gridBagConstraintsX);
            panelToolbar.add(getOptionsButton(), gridBagConstraintsy);
        }
        return panelToolbar;
    }

    private JButton getSaveButton() {
        if (saveButton == null) {
            saveButton = new JButton();
            saveButton.setText(
                    this.extension.getMessages().getString("recordsattack.toolbar.button.save"));
            saveButton.setIcon(
                    new ImageIcon(
                            RecordsPanel.class.getResource("/resource/icon/fugue/database.png")));
            saveButton.setEnabled(false);
            saveButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            logger.info("Press on save");
                            logger.error("Press on save");
                            /*
                             * logger.info("Appuie sur Save Button");
                             *
                             * for (HistoryReference reference : spiderResultsTableModel
                             * .getExtensionHistory() .getSelectedHistoryReferences()) { logger.info("id :"
                             * + reference.getHistoryId()); logger.info("type :" + reference.getMethod()); }
                             * extension.showSaveDialog(null);
                             *
                             * for (AjaxSpiderTableEntry entry : spiderResultsTableModel.getResources()) {
                             * logger.info("entry id :" + entry.getHistoryId()); logger.info("method :" +
                             * entry.getMethod()); logger.info(" History reference : " +
                             * entry.getHistoryReference()); try { logger.info( "hsitory reference" +
                             * entry.getHistoryReference() .getHttpMessage() .getRequestBody() .toString());
                             * } catch (HttpMalformedHeaderException | DatabaseException e1) { // TODO
                             * Auto-generated catch block e1.printStackTrace(); } }
                             */
                            extension.showSaveDialog(null);
                        }
                    });
        }
        return saveButton;
    }

    /** @return The Start Scan Button */
    private JButton getStartRecordsButton() {
        if (startRecordsButton == null) {
            startRecordsButton = new JButton();
            startRecordsButton.setText(
                    this.extension.getMessages().getString("recordsattack.toolbar.button.start"));
            startRecordsButton.setIcon(
                    new ImageIcon(RecordsPanel.class.getResource("/resource/icon/10/093.png")));
            startRecordsButton.setEnabled(!Mode.safe.equals(Control.getSingleton().getMode()));
            startRecordsButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            extension.showScanDialog(null);
                        }
                    });
        }
        return startRecordsButton;
    }

    /** @return The Stop Scan Button */
    private JButton getStopRecordsButton() {
        if (stopRecordsButton == null) {
            stopRecordsButton = new JButton();
            stopRecordsButton.setToolTipText(
                    this.extension.getMessages().getString("recordsattack.toolbar.button.stop"));
            stopRecordsButton.setIcon(
                    new ImageIcon(RecordsPanel.class.getResource("/resource/icon/16/142.png")));
            stopRecordsButton.setEnabled(false);
            stopRecordsButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            stopRecord();
                        }
                    });
        }
        return stopRecordsButton;
    }

    /** @return the Options Button */
    private JButton getOptionsButton() {
        if (optionsButton == null) {
            optionsButton = new JButton();
            optionsButton.setToolTipText(
                    this.extension.getMessages().getString("spiderajax.options.title"));
            optionsButton.setIcon(
                    new ImageIcon(RecordsPanel.class.getResource("/resource/icon/16/041.png")));
            optionsButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            Control.getSingleton()
                                    .getMenuToolsControl()
                                    .options(
                                            extension
                                                    .getMessages()
                                                    .getString("spiderajax.options.title"));
                        }
                    });
        }
        return optionsButton;
    }

    public void stopRecord() {
        this.getStartRecordsButton().setEnabled(true);
        this.getStopRecordsButton().setEnabled(false);
        this.getSaveButton().setEnabled(true);
        // Stop intercept requests
        this.extension.getProxyRecordsListener().stopRecord();
    }

    public void startRecord() {
        this.getStartRecordsButton().setEnabled(false);
        this.getStopRecordsButton().setEnabled(true);
        this.getSaveButton().setEnabled(false);
    }

    /**
     * This method initializes the scrollLog attribute
     *
     * @return javax.swing.JScrollPane
     */
    private javax.swing.JScrollPane getScrollLog() {
        if (scrollLog == null) {
            scrollLog = new javax.swing.JScrollPane();
            scrollLog.setViewportView(getRecordResultsTable());

            scrollLog.setName("scrollLog");
        }
        return scrollLog;
    }

    private HistoryReferencesTable getRecordResultsTable() {
        if (spiderResultsTable == null) {
            spiderResultsTable = new RecordsResultsTable(spiderResultsTableModel);
        }
        return spiderResultsTable;
    }

    @Override
    public void spiderStarted() {
        // TODO Auto-generated method stub

    }

    private void resetPanelState() {}

    /**
     * @param historyReference history reference
     * @param msg the http message
     * @param url the targeted url
     */
    private boolean addHistoryUrl(
            HistoryReference historyReference, HttpMessage msg, ResourceState state) {

        this.spiderResultsTableModel.addHistoryReference(historyReference, state);
        return true;
    }

    @Override
    public void spiderStopped() {
        logger.info("Spider spiderStopped");
    }

    @Override
    public void foundMessage(
            HistoryReference historyReference, HttpMessage httpMessage, ResourceState state) {
        boolean added = addHistoryUrl(historyReference, httpMessage, state);
        if (View.isInitialised() && added) {
            foundCount++;
            this.foundLabel.setText(Integer.toString(this.foundCount));
        }
    }
}
