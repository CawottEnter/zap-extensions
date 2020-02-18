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
package org.zaproxy.zap.extension.recordsattack.scenarioModel;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.util.*;
import java.util.List;
import javax.swing.*;
import org.apache.log4j.Logger;
import org.parosproxy.paros.view.MainFrame;
import org.zaproxy.zap.extension.recordsattack.ExtensionRecordsAttack;
import org.zaproxy.zap.extension.recordsattack.Scenario;
import org.zaproxy.zap.extension.recordsattack.serializableHelper.ScenarioSerializable;

public class TreeScenarioDialog extends JFrame {
    private static final Logger logger = Logger.getLogger(TreeScenarioDialog.class);

    private static final long serialVersionUID = 1674L;
    private ExtensionRecordsAttack extension;
    private JList<ScenarioSerializable> scenariosList;
    private JPanel panel;
    private DefaultListModel<ScenarioSerializable> listModel =
            new DefaultListModel<ScenarioSerializable>();
    private ScenarioRenderer scenarioRenderer;

    public TreeScenarioDialog(ExtensionRecordsAttack ext, MainFrame owner, Dimension dim) {
        super("Scenarios");
        setBounds(0, 0, 600, 400);
        this.extension = ext;
        scenariosList = new JList<ScenarioSerializable>(listModel);
        scenarioRenderer = new ScenarioRenderer();
        scenariosList.setCellRenderer(scenarioRenderer);
    }

    public void initialize() {
        logger.info("in initialize");
        this.setLayout(new BorderLayout());
        List<Scenario> scenarios = this.extension.getScenarios();
        logger.info("Scenarios size : " + scenarios.size());
        updateListModel();
        this.setLayout(new BorderLayout());
        // this.add(getPanel(), java.awt.BorderLayout.CENTER);
        this.getContentPane().add(getPanel());
    }

    private void updateListModel() {
        List<Scenario> scenarios = this.extension.getScenarios();
        if (scenarios.isEmpty()) {
            logger.info("No Scenario");
        } else {
            listModel.clear();
            scenarios.forEach(
                    t -> {
                        listModel.addElement(t.getScenarioSerializable());
                    });
        }
    }

    private javax.swing.JPanel getPanel() {
        if (panel == null) {
            panel = new JPanel();
            panel.setLayout(new java.awt.GridBagLayout());
            panel.setName("BLABLA");

            JButton saveScenarios = new JButton();
            saveScenarios.setText("Sauvegarder Scenarios");
            saveScenarios.addActionListener(saveScenarios(this, this.extension));
            JButton loadScenarios = new JButton();
            loadScenarios.setText("Load scenarios");
            loadScenarios.addActionListener(loadScenarios(this, this.extension));

            JButton replayScenario = new JButton();
            replayScenario.setText("Replay Scenario");
            replayScenario.addActionListener(replayScenario(this));

            GridBagConstraints gridBagConstraints = new GridBagConstraints();
            gridBagConstraints.weightx = 0.5;
            gridBagConstraints.gridx = 0;
            gridBagConstraints.gridy = 0;
            panel.add(saveScenarios, gridBagConstraints);

            gridBagConstraints.gridx = 1;
            panel.add(loadScenarios, gridBagConstraints);

            gridBagConstraints.ipady = 40;
            gridBagConstraints.weightx = 0;
            gridBagConstraints.gridwidth = 7;
            gridBagConstraints.gridy = 1;
            panel.add(scenariosList, gridBagConstraints);
            gridBagConstraints.gridx = 2;
            gridBagConstraints.gridy = 1;
            panel.add(replayScenario, gridBagConstraints);
        }
        return panel;
    }

    private ActionListener replayScenario(TreeScenarioDialog treeScenarioDialog) {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                logger.info("Debut du replay :)");
                ScenarioSerializable scenarioSerializableSelected =
                        scenariosList.getSelectedValue();
                Scenario scenario =
                        scenarioSerializableSelected.toScenario(treeScenarioDialog.extension);
                scenario.replayScenario();
                logger.info("Fin du replay");
            }
        };
    }

    private ActionListener saveScenarios(JFrame frame, ExtensionRecordsAttack extension) {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Specify a file to save");
                int userSelection = fileChooser.showSaveDialog(frame);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File fileToSave = fileChooser.getSelectedFile();
                    logger.info("Save as : " + fileToSave);
                    ObjectOutputStream oos = null;
                    List<Scenario> scenarios = extension.getScenarios();
                    List<ScenarioSerializable> scenarioSerializables = new ArrayList<>();
                    scenarios.forEach(
                            t -> {
                                scenarioSerializables.add(t.getScenarioSerializable());
                            });
                    try {
                        oos = new ObjectOutputStream(new FileOutputStream(fileToSave));
                        oos.writeObject(scenarioSerializables);

                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }

                    logger.info("Serialisation terminée avec succès...");
                }
            }
        };
    }

    @SuppressWarnings("unchecked")
    private ActionListener loadScenarios(JFrame frame, ExtensionRecordsAttack extension) {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Specify a file to load");
                int userSelection = fileChooser.showSaveDialog(frame);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File fileToSave = fileChooser.getSelectedFile();
                    ObjectMapper objectMapper = new ObjectMapper();
                    List<ScenarioSerializable> scenarios = null;
                    try {
                        ObjectInputStream ois =
                                new ObjectInputStream(new FileInputStream(fileToSave));
                        scenarios = (List<ScenarioSerializable>) ois.readObject();
                        logger.info("load as : " + fileToSave);
                        scenarios.forEach(
                                t -> {
                                    extension.getScenarios().add(t.toScenario(extension));
                                });
                        logger.info("_debug liste size : " + scenarios.size());
                        logger.info("Déserialisation terminée avec succès...");
                        updateListModel();
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    } catch (ClassNotFoundException ex) {
                        ex.printStackTrace();
                    }
                }
            }
        };
    }
}
