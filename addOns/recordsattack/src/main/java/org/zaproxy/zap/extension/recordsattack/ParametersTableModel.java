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
import org.apache.commons.lang3.ArrayUtils;

public class ParametersTableModel extends AbstractTableModel {
    /** */
    private static final long serialVersionUID = -5012695302760110023L;

    private String[] columnsHeader = null;

    private Object[][] rows = new Object[0][0];

    public ParametersTableModel(String[][] columns, String[] headers) {
        this.columnsHeader = headers;
        this.rows = columns;
    }

    public void setHeader(String[] newHeaders) {
        columnsHeader = newHeaders;
    }

    @Override
    public int getColumnCount() {
        return columnsHeader.length;
    }

    @Override
    public int getRowCount() {
        return rows.length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        return rows[rowIndex][columnIndex];
    }

    public String getColumnName(int col) {
        return columnsHeader[col];
    }

    public boolean isCellEditable(int row, int column) {
        // Aucune cellule �ditable
        return false;
    }

    public void removeRows() {
        this.rows = new Object[0][0];
    }

    /**
     * Permet d'ajouter une ligne dans le tableau
     *
     * @param data
     */
    public void addRow(Object[] data) {
        int indice = 0, nbRow = this.getRowCount(), nbCol = this.getColumnCount();
        Object temp[][] = this.rows;
        this.rows = new Object[nbRow + 1][nbCol];
        for (Object[] value : temp) {
            this.rows[indice++] = value;
        }
        this.rows[indice] = data;
        temp = null;
        // Cette m�thode permet d'avertir le tableau que les donn�es ont �t� modifi�es
        // Ce qui permet une mise � jours compl�te du tableau
        this.fireTableDataChanged();
    }

    /** Permet d'ajouter plusieurs lignes */
    public void setData(Object[][] data) {
        for (int i = 0; i < data.length; i++) {
            addRow(data[i]);
        }
    }

    public Object[] removeRow(int id) {
        Object[] rowToReturn = this.rows[id];
        this.rows = ArrayUtils.remove(this.rows, id);
        this.fireTableDataChanged();
        return rowToReturn;
    }
}
