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

import javax.swing.table.AbstractTableModel;

public class ParametersTableModel extends AbstractTableModel {
    /** */
    private static final long serialVersionUID = -5012695302760110023L;

    private final String[] headers = {"NAME", "VALUE"};

    private String[][] data = {{"oui", "non"}, {"oui", "non"}};

    public ParametersTableModel() {
        super();
    }

    @Override
    public int getColumnCount() {
        return headers.length;
    }

    @Override
    public int getRowCount() {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public Object getValueAt(int arg0, int arg1) {
        // TODO Auto-generated method stub
        return null;
    }

    public String getColumnName(int col) {
        return headers[col];
    }
}
