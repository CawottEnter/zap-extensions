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

import java.awt.*;
import javax.swing.*;
import org.zaproxy.zap.extension.recordsattack.serializableHelper.ScenarioSerializable;

public class ScenarioRenderer extends JLabel implements ListCellRenderer<ScenarioSerializable> {
    private static final long serialVersionUID = 2120540540L;

    public ScenarioRenderer() {
        setOpaque(true);
    }

    @Override
    public Component getListCellRendererComponent(
            JList<? extends ScenarioSerializable> list,
            ScenarioSerializable scenarioSerializable,
            int index,
            boolean isSelected,
            boolean cellHasFocus) {
        String name = "plouf : " + scenarioSerializable.getName();
        setText(name);
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        if (isSelected) {
            setBackground(Color.BLUE);
            setForeground(Color.BLUE);
        } else {
            setBackground(Color.CYAN);
            setForeground(list.getForeground());
        }
        // @TODO rajouter icone lors du check
        return this;
    }
}
