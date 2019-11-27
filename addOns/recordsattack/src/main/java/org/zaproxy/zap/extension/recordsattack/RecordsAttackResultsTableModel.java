package org.zaproxy.zap.extension.recordsattack;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.view.table.AbstractCustomColumnHistoryReferencesTableModel;
import org.zaproxy.zap.view.table.DefaultHistoryReferencesTableEntry;
import org.zaproxy.zap.view.table.HistoryReferencesTableModel.Column;

public class RecordsAttackResultsTableModel extends AbstractCustomColumnHistoryReferencesTableModel<RecordsAttackResultsTableModel.AjaxSpiderTableEntry> {
    /**
	 * 
	 */
	private static final long serialVersionUID = 2310687869097101584L;


	private final ExtensionHistory extensionHistory;


    private static final Column[] COLUMNS =
            new Column[] {
                Column.CUSTOM,
                Column.HREF_ID,
                Column.REQUEST_TIMESTAMP,
                Column.RESPONSE_TIMESTAMP,
                Column.METHOD,
                Column.URL,
                Column.STATUS_CODE,
                Column.STATUS_REASON,
                Column.RTT,
                Column.SIZE_REQUEST_HEADER,
                Column.SIZE_REQUEST_BODY,
                Column.SIZE_RESPONSE_HEADER,
                Column.SIZE_RESPONSE_BODY,
                Column.HIGHEST_ALERT,
                Column.NOTE,
                Column.TAGS
            };
    private static final String[] CUSTOM_COLUMN_NAMES = {
            Constant.messages.getString("spiderajax.panel.table.header.processed")
        };

        private static final EnumMap<ResourceState, ProcessedCellItem> statesMap;

        private final ExtensionHistory extensionHistory;
        private AlertEventConsumer alertEventConsumer;

        private List<AjaxSpiderTableEntry> resources;
        private Map<Integer, Integer> idsToRows;
	

    static class AjaxSpiderTableEntry extends DefaultHistoryReferencesTableEntry {

        private final ResourceState state;

        public AjaxSpiderTableEntry(HistoryReference historyReference, ResourceState state) {
            super(historyReference, COLUMNS);
            this.state = state;
        }

        public ResourceState getResourceState() {
            return state;
        }
    }
}
