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
import java.util.ArrayList;
import java.util.List;
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
    private JButton saveButton;
    private JButton startRecordAuthentification;
    private JLabel foundLabel = new JLabel();
    private ScanStatus scanStatus = null;

    private RecordsResultsTable spiderResultsTable;

    private RecordsAttackResultsTableModel spiderResultsTableModel =
            new RecordsAttackResultsTableModel();

    private int foundCount = 0;

    private JButton scenarioDialogButton;

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
            GridBagConstraints gridBagConstraints6 = new GridBagConstraints();
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
            gridBagConstraints6.gridx = 5;
            gridBagConstraints6.gridy = 0;
            gridBagConstraints6.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints6.anchor = java.awt.GridBagConstraints.WEST;
            gridBagConstraintsX.gridx = 6;
            gridBagConstraintsX.gridy = 0;
            gridBagConstraintsX.weightx = 1.0;
            gridBagConstraintsX.weighty = 1.0;
            gridBagConstraintsX.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraintsX.anchor = java.awt.GridBagConstraints.EAST;
            gridBagConstraintsX.fill = java.awt.GridBagConstraints.HORIZONTAL;
            JLabel t1 = new JLabel();

            panelToolbar.add(getStartRecordsButton(), gridBagConstraints1);
            panelToolbar.add(getScenarioDialogButton(), gridBagConstraints2);
            // panelToolbar.add(getScenarioDialogButton(), gridBagConstraints3);

            // panelToolbar.add(getScenarioDialogButton(), gridBagConstraints4);

            panelToolbar.add(getSaveButton(), gridBagConstraints5);
            panelToolbar.add(getstartRecordAuthentification(), gridBagConstraints6);

            panelToolbar.add(t1, gridBagConstraintsX);
        }
        return panelToolbar;
    }

    private JButton getScenarioDialogButton() {
        if (scenarioDialogButton == null) {
            scenarioDialogButton = new JButton();
            scenarioDialogButton.setText("Scenario");
            scenarioDialogButton.setEnabled(true);
            scenarioDialogButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            extension.showScenarioDialog(null);
                            logger.info("WARZAZAT");
                        }
                    });
        }
        return scenarioDialogButton;
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
            startRecordsButton.addActionListener(startRecordsAction(this.extension));
        }
        return startRecordsButton;
    }

    private ActionListener startRecordsAction(ExtensionRecordsAttack extension) {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                extension.startRecord();
            }
        };
    }

    private ActionListener stopRecordsAction(ExtensionRecordsAttack extension) {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                stopRecord();
            }
        };
    }

    private JButton getstartRecordAuthentification() {
        if (startRecordAuthentification == null) {
            startRecordAuthentification = new JButton();
            startRecordAuthentification.setEnabled(true);
            startRecordAuthentification.setText(
                    this.extension
                            .getMessages()
                            .getString("recordsattack.toolbar.button.record.authentification"));
            startRecordAuthentification.setToolTipText(
                    this.extension
                            .getMessages()
                            .getString("recordsattack.toolbar.button.record.authentification"));
            startRecordAuthentification.setIcon(
                    new ImageIcon(RecordsPanel.class.getResource("/resource/icon/16/008.png")));
            startRecordAuthentification.addActionListener(
                    getRecordAuthentificationActionListener());
        }
        return startRecordAuthentification;
    }

    public void stopRecord() {
        this.getStartRecordsButton().setEnabled(true);
        for (ActionListener action : this.getStartRecordsButton().getActionListeners())
            this.getStartRecordsButton().removeActionListener(action);
        this.getStartRecordsButton().addActionListener(startRecordsAction(this.extension));
        getStartRecordsButton()
                .setText(
                        this.extension
                                .getMessages()
                                .getString("recordsattack.toolbar.button.start"));
        this.getSaveButton().setEnabled(true);
        logger.info("_debug ici suppression de la table");
        this.extension.getProxyRecordsListener().stopRecord();
    }

    public void startRecord() {
        /*
        On modifie le nom du boutton
         */
        this.getStartRecordsButton().setEnabled(true);
        getStartRecordsButton()
                .setText(
                        this.extension
                                .getMessages()
                                .getString("recordsattack.toolbar.button.stop"));
        for (ActionListener action : this.getStartRecordsButton().getActionListeners())
            this.getStartRecordsButton().removeActionListener(action);

        this.getStartRecordsButton().addActionListener(stopRecordsAction(extension));
    }

    private ActionListener getRecordAuthentificationActionListener() {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                logger.info("Start Authentification");
                startRecordAuthentification();
            }
        };
    }

    private ActionListener getStopRecordAuthentificationActionListener() {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                logger.info("Stop Authentification");

                stopRecordAuthentification();
            }
        };
    }

    private void startRecordAuthentification() {
        for (ActionListener action : this.getstartRecordAuthentification().getActionListeners())
            this.getstartRecordAuthentification().removeActionListener(action);
        this.getstartRecordAuthentification()
                .addActionListener(getStopRecordAuthentificationActionListener());
        this.getstartRecordAuthentification()
                .setText(
                        this.extension
                                .getMessages()
                                .getString(
                                        "recordsattack.toolbar.button.stop.record.authentification"));
        this.extension.showAuthentificationDialog(null);
    }

    private void stopRecordAuthentification() {
        for (ActionListener action : this.getstartRecordAuthentification().getActionListeners())
            this.getstartRecordAuthentification().removeActionListener(action);
        this.getstartRecordAuthentification()
                .addActionListener(getRecordAuthentificationActionListener());
        this.getstartRecordAuthentification()
                .setText(
                        this.extension
                                .getMessages()
                                .getString("recordsattack.toolbar.button.record.authentification"));
        this.extension.getProxyRecordsListener().stopRecord();

        String nameAuthentification =
                this.extension.getAuthentificationDialog().getNameAuthentification();
        String descritionAuthentification =
                this.extension.getAuthentificationDialog().getDescriptionAuthentification();
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
                new Authentification(nameAuthentification, descritionAuthentification, references);
        this.extension.getAuthentification().add(authentification);
        this.extension.getRecordsPanel().getRecordsAttackResultsTableModel().clear();
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

    /**
     * @param historyReference history reference
     * @param msg the http message
     */
    private boolean addHistoryUrl(
            HistoryReference historyReference, HttpMessage msg, ResourceState state) {

        this.spiderResultsTableModel.addHistoryReference(historyReference, state);
        return true;
    }

    public void clearHistoryUrl() {
        this.spiderResultsTableModel.clear();
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
