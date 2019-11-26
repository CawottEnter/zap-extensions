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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JLabel;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.Model;

public class RecordsPanel extends AbstractPanel {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = Logger.getLogger(RecordsPanel.class);

    private javax.swing.JScrollPane scrollLog = null;
    private ExtensionRecordsAttack extension = null;
    private javax.swing.JPanel recordsAttackPanel = null;
    private javax.swing.JToolBar panelToolbar = null;
    private JButton startRecordsButton;
    private JButton stopRecordsButton;

    /** This is the default constructor */
    public RecordsPanel(ExtensionRecordsAttack e) {
        super();
        this.extension = e;
        initialize();
    }

    /** This method initializes this class and its attributes */
    @SuppressWarnings("deprecation")
    private void initialize() {
        this.setLayout(new BorderLayout());
        if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
            this.setSize(600, 200);
        }
        this.add(getRecordsAttackPanel(), java.awt.BorderLayout.CENTER);
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
        }
        return panelToolbar;
    }

    /** @return The Start Scan Button */
    private JButton getStartRecordsButton() {
        if (startRecordsButton == null) {
            startRecordsButton = new JButton();
            startRecordsButton.setText(
                    this.extension.getMessages().getString("requestRecords.toolbar.button.start"));
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
                    this.extension.getMessages().getString("requestRecords.toolbar.button.stop"));
            stopRecordsButton.setEnabled(false);
        }
        return stopRecordsButton;
    }

    /**
     * This method initializes the scrollLog attribute
     *
     * @return javax.swing.JScrollPane
     */
    private javax.swing.JScrollPane getScrollLog() {
        if (scrollLog == null) {
            scrollLog = new javax.swing.JScrollPane();

            scrollLog.setName("scrollLog");
        }
        return scrollLog;
    }
    
    
    private void startRecord(String displayName) {
        this.getStartRecordsButton().setEnabled(false);
        this.getStopRecordsButton().setEnabled(true);
        ProxyListenerLog proxyListener = null; 
        Control control = org.parosproxy.paros.control.Control.getSingleton();
        control.getProxy().
        ExtensionHistory extHist = org.parosproxy.paros.control.Control.getSingleton().
                getExtensionLoader().getExtension(ExtensionHistory.NAME);
        if (extHist != null) {
            // You can now access the history list via:
            extHist.getHistoryList();
        }

    }
}
