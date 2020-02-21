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
package org.zaproxy.zap.extension.seleniumrectorat;

import net.sf.json.JSONObject;
import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.api.*;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.ApiUtils;

public class SeleniumRectoratAPI extends ApiImplementor {
    private static final Logger logger = Logger.getLogger(SeleniumRectoratAPI.class);
    private static final String PREFIX = "seleniumrectorat";

    private static final String ACTION_START_RECORDS_AUTHENTIFICATION =
            "startRecordsAuthentification";
    private static final String ACTION_STOP_RECORDS_AUTHENTIFICATION =
            "stopRecordsAuthentification";

    private static final String ACTION_START_ATTACK = "startAttack";
    private static final String ACTION_STOP_ATTACK = "stopAttack";

    private static final String PARAM_CONTEXT_NAME = "ContextName";

    private ExtensionSeleniumRectorat extension;

    public SeleniumRectoratAPI(ExtensionSeleniumRectorat seleniumRectoratExtension) {
        this.extension = seleniumRectoratExtension;
        ApiAction startRecordAuthentification =
                new ApiAction(
                        ACTION_START_RECORDS_AUTHENTIFICATION,
                        new String[] {PARAM_CONTEXT_NAME},
                        null);
        this.addApiAction(startRecordAuthentification);

        ApiAction stopRecordAuthentification = new ApiAction(ACTION_STOP_RECORDS_AUTHENTIFICATION);
        this.addApiAction(stopRecordAuthentification);

        ApiAction startAttack = new ApiAction(ACTION_START_ATTACK);
        this.addApiAction(startAttack);

        ApiAction stopAttack = new ApiAction(ACTION_STOP_ATTACK);
        this.addApiAction(stopAttack);
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        Context context = null;
        logger.info("_debug input in handle API");
        switch (name) {
            case ACTION_START_RECORDS_AUTHENTIFICATION:
                {
                    logger.info("_debug in action start records");
                    if (params.containsKey(PARAM_CONTEXT_NAME)
                            && params.getString(PARAM_CONTEXT_NAME) != null
                            && !params.getString(PARAM_CONTEXT_NAME).isEmpty()) {
                        if (this.extension.getAuthentificationRecord())
                            return ApiResponseElement.FAIL;
                        logger.info("_debug rentre après le if");
                        String contextName = params.getString(PARAM_CONTEXT_NAME);
                        context = ApiUtils.getContextByName(contextName);
                        this.extension.setContext(context);
                        this.extension.startAuthentification();
                        logger.info(
                                "_debug StartAuthentification getAuthentification : "
                                        + this.extension.getAuthentificationRecord());

                        logger.info("ok pour l enbvoie de l'authentification");
                    } else {
                        return ApiResponseElement.FAIL;
                    }
                    break;
                }
            case ACTION_STOP_RECORDS_AUTHENTIFICATION:
                {
                    logger.info(
                            "_debug getAuthentification : "
                                    + this.extension.getAuthentificationRecord());
                    this.extension
                            .getProxyListener()
                            .getParameters()
                            .forEach(
                                    t -> {
                                        logger.info(t);
                                    });
                    if (this.extension.getAuthentificationRecord()) {
                        this.extension.stopAuthentification();
                    } else {
                        return ApiResponseElement.FAIL;
                    }
                    break;
                }
            case ACTION_START_ATTACK:
                {
                    logger.info("Start attack");
                    if (this.extension.getAuthentificationRecord()) return ApiResponseElement.FAIL;
                    this.extension.startAttack();
                    return ApiResponseElement.OK;
                }
            case ACTION_STOP_ATTACK:
                {
                    if (this.extension.getAttackMode()) {
                        this.extension.stopAttack();
                        return ApiResponseElement.OK;
                    }
                    return ApiResponseElement.FAIL;
                }
        }
        return ApiResponseElement.OK;
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }
}
