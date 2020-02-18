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
package org.zaproxy.zap.extension.recordsattack;

import net.sf.json.JSONObject;
import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.api.*;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.ApiUtils;

public class RecordsAttackAPI extends ApiImplementor {
    private static final Logger logger = Logger.getLogger(RecordsAttackAPI.class);

    private static final String PREFIX = "recordsAttack";

    private static final String ACTION_START_RECORDS_AUTHENTIFICATION =
            "startRecordsAuthentification";
    private static final String ACTION_STOP_RECORDS_AUTHENTIFICATION =
            "stopRecordsAuthentification";

    private static final String PARAM_NAME = "Name";
    private static final String PARAM_DESCRIPTION = "Description";
    private static final String PARAM_CONTEXT_NAME = "contextName";

    private enum RecordsAttackStatus {
        STOPPED,
        RUNNING;

        @Override
        public String toString() {
            return super.toString().toLowerCase();
        }
    }

    private ExtensionRecordsAttack extension;

    public RecordsAttackAPI(ExtensionRecordsAttack extension) {
        this.extension = extension;
        ApiAction scan =
                new ApiAction(
                        ACTION_START_RECORDS_AUTHENTIFICATION,
                        new String[] {PARAM_CONTEXT_NAME},
                        new String[] {PARAM_NAME, PARAM_DESCRIPTION});
        scan.setDescriptionTag("spiderajax.api.action.scan");
        this.addApiAction(scan);

        ApiAction stopRecordAuthentification = new ApiAction(ACTION_STOP_RECORDS_AUTHENTIFICATION);
        stopRecordAuthentification.setDescriptionTag("Stop record authentification");
        this.addApiAction(stopRecordAuthentification);
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        Context context = null;
        switch (name) {
            case ACTION_START_RECORDS_AUTHENTIFICATION:

                // @TODO verifier si une action n'est pas en cours
                if (params.containsKey(PARAM_CONTEXT_NAME)) {
                    String contextName = params.getString(PARAM_CONTEXT_NAME);
                    if (!contextName.isEmpty()) {
                        context = ApiUtils.getContextByName(contextName);
                        String nameAuthentification =
                                ApiUtils.getNonEmptyStringParam(params, PARAM_NAME);
                        String descriptionAuthentification =
                                ApiUtils.getNonEmptyStringParam(params, PARAM_DESCRIPTION);
                        startRecordAuthentification(
                                context, nameAuthentification, descriptionAuthentification);
                    }
                }
                break;
            case ACTION_STOP_RECORDS_AUTHENTIFICATION:
                break;
        }
        return ApiResponseElement.OK;
    }

    private void startRecordAuthentification(
            Context context, String nameAuthentification, String descriptionAuthentification) {
        this.extension.setContext(context);
        this.extension.getProxyRecordsListener().runRecord();
    }

    private void stopRecordAuthentification() {}

    @Override
    public String getPrefix() {
        return PREFIX;
    }
}
