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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.sf.json.JSON;
import net.sf.json.JSONObject;
import org.apache.log4j.Logger;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;

public class RecordsAttackAPI extends ApiImplementor implements SpiderListener {
    private static final Logger logger = Logger.getLogger(RecordsAttackAPI.class);
    private static final String PREFIX = "recordRequest";

    private static final String ACTION_START_RECORD = "record";
    private static final String ACTION_STOP_RECORD = "stopRecord";

    private static final String VIEW_STATUS = "status";
    private static final String VIEW_RESULTS = "results";

    private static final String PARAM_URL = "url";
    private static final String PARAM_SUBTREE_ONLY = "subtreeOnly";
    private static final String PARAM_START = "start";
    private static final String PARAM_COUNT = "count";

    private RecordThread recordThread;

    private final ExtensionRecordsAttack extension;

    private enum RecordRequestStatus {
        STOPPED,
        RUNNING;

        @Override
        public String toString() {
            return super.toString().toLowerCase();
        }
    }

    private List<HistoryReference> historyReferences;

    /** Provided only for API client generator usage. */
    public RecordsAttackAPI(ExtensionRecordsAttack extension) {
        this.extension = extension;
        this.historyReferences = Collections.emptyList();

        ApiAction record =
                new ApiAction(
                        ACTION_START_RECORD, null, new String[] {PARAM_URL, PARAM_SUBTREE_ONLY});
        record.setDescriptionTag("records.api.action.scan");

        ApiAction stopRecord =
                new ApiAction(ACTION_STOP_RECORD, new String[] {PARAM_URL, PARAM_SUBTREE_ONLY});
        stopRecord.setDescriptionTag("recordsattack.api.action.scanAsUser");
        this.addApiAction(stopRecord);
        this.addApiView(new ApiView(VIEW_STATUS));
        this.addApiView(new ApiView(VIEW_RESULTS, null, new String[] {PARAM_START, PARAM_COUNT}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        switch (name) {
            case ACTION_START_RECORD:
                if (extension.isRecordRunning()) {
                    throw new ApiException(ApiException.Type.SCAN_IN_PROGRESS);
                }

                startRecord();
                break;
        }

        return ApiResponseElement.OK;
    }

    private void startRecord() {
        String displayName = "API - TOTO";
        recordThread = extension.createSpiderThread(this);
    }

    @Override
    public void spiderStarted() {
        historyReferences = Collections.synchronizedList(new ArrayList<HistoryReference>());
    }

    @Override
    public void foundMessage(
            HistoryReference historyReference, HttpMessage httpMessage, ResourceState state) {
        historyReferences.add(historyReference);
    }

    @Override
    public void spiderStopped() {}

    private static Map<String, String> createDataMap(HistoryReference hr) {
        Map<String, String> map = new HashMap<>();
        map.put("messageId", Integer.toString(hr.getHistoryId()));
        map.put("method", hr.getMethod());
        map.put("url", hr.getURI().toString());
        map.put("statusCode", Integer.toString(hr.getStatusCode()));
        map.put("statusReason", hr.getReason());
        return map;
    }

    private static ApiResponse resourceToSet(HistoryReference hr) {
        return new ApiResponseSet<String>("resource", createDataMap(hr));
    }

    private ApiResponseSet<String> recordResourceToSet(RecordResource recordResource) {
        Map<String, String> map = createDataMap(recordResource.getHistoryReference());
        map.put("state", recordResource.getState().toString());
        return new ApiResponseSet<String>("resource", map);
    }

    private static class RecordResource {
        private final HistoryReference historyReference;
        private final ResourceState state;

        public RecordResource(HistoryReference historyReference, ResourceState state) {
            this.historyReference = historyReference;
            this.state = state;
        }

        public HistoryReference getHistoryReference() {
            return historyReference;
        }

        public ResourceState getState() {
            return state;
        }
    }

    private static class FullResultsApiResponse extends ApiResponse {
        private final ApiResponseList inScope;

        public FullResultsApiResponse(String name, List<HistoryReference> historyReferences) {
            super(name);

            inScope = new ApiResponseList("inScope");
            synchronized (historyReferences) {
                for (HistoryReference hr : historyReferences) {
                    inScope.addItem(resourceToSet(hr));
                }
            }
        }

        private static ApiResponse resourceToSet(HistoryReference hr) {
            return new ApiResponseSet<String>("resource", createDataMap(hr));
        }

        private static Map<String, String> createDataMap(HistoryReference hr) {
            Map<String, String> map = new HashMap<>();
            map.put("messageId", Integer.toString(hr.getHistoryId()));
            map.put("method", hr.getMethod());
            map.put("url", hr.getURI().toString());
            map.put("statusCode", Integer.toString(hr.getStatusCode()));
            map.put("statusReason", hr.getReason());
            return map;
        }

        private ApiResponseSet<String> spiderResourceToSet(RecordResource recordResource) {
            Map<String, String> map = createDataMap(recordResource.getHistoryReference());
            map.put("state", recordResource.getState().toString());
            return new ApiResponseSet<String>("resource", map);
        }

        @Override
        public void toXML(Document doc, Element parent) {
            parent.setAttribute("type", "set");
            Element el = doc.createElement("not implemented");
            inScope.toXML(doc, el);
            parent.appendChild(el);
        }

        @Override
        public JSON toJSON() {
            JSONObject scopes = new JSONObject();

            scopes.put("not implemented", ((JSONObject) inScope.toJSON()).get(inScope.getName()));
            JSONObject jo = new JSONObject();
            jo.put(getName(), scopes);
            return jo;
        }

        @Override
        public void toHTML(StringBuilder sb) {
            sb.append("<h2>" + this.getName() + "</h2>\n");
            inScope.toHTML(sb);
        }

        @Override
        public String toString(int indent) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < indent; i++) {
                sb.append("\t");
            }
            sb.append("ApiResponseSet ");
            sb.append(this.getName());
            sb.append(" : [\n");
            sb.append(inScope.toString(indent + 1));
            for (int i = 0; i < indent; i++) {
                sb.append("\t");
            }
            sb.append("]\n");
            return sb.toString();
        }
    }
}
