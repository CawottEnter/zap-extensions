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
package org.zaproxy.zap.extension.recordsattack.serializableHelper;

import java.io.Serializable;
import java.util.Arrays;
import org.apache.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.*;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;

public class Message implements Serializable {
    private static final Logger logger = Logger.getLogger(Message.class);
    private static final long serialVersionUID = 354054054054L;
    HttpRequestHeader reqHeader;
    HttpResponseHeader resHeader;
    byte[] resHttpBody;
    byte[] reqHttpBody;

    public Message(HttpMessage message) {

        reqHeader = message.getRequestHeader();
        logger.info("req header = " + reqHeader.toString());
        resHeader = message.getResponseHeader();
        reqHttpBody = message.getRequestBody().getBytes();
        resHttpBody = message.getResponseBody().getBytes();
    }

    public Message(HistoryReference reference)
            throws DatabaseException, HttpMalformedHeaderException {
        this(reference.getHttpMessage());
    }

    public HttpMessage toHttpMessage() {
        HttpRequestBody reqBody = new HttpRequestBody();
        reqBody.setBody(reqHttpBody);
        HttpResponseBody resBody = new HttpResponseBody(resHttpBody);
        HttpMessage message = new HttpMessage(reqHeader, reqBody, resHeader, resBody);
        return message;
    }

    public void compare(HttpMessage message) {
        HttpMessage messageBis = toHttpMessage();
        HttpRequestHeader mBisReqHeader = messageBis.getRequestHeader();
        HttpRequestBody mBisReqBody = messageBis.getRequestBody();
        HttpResponseHeader mBisResHeader = messageBis.getResponseHeader();
        HttpResponseBody mBisResBody = messageBis.getResponseBody();

        HttpRequestHeader mReqHeader = message.getRequestHeader();
        HttpRequestBody mReqBody = message.getRequestBody();
        HttpResponseHeader mResHeader = message.getResponseHeader();
        HttpResponseBody mResBody = message.getResponseBody();
        logger.info("_debug compare ");
        logger.info(mBisReqHeader.getMethod().equals(mReqHeader.getMethod()));
        logger.info(mBisReqHeader.getURI().toString().equals(mReqHeader.getURI().toString()));
        logger.info(mBisReqHeader.getHeadersAsString().equals(mReqHeader.getHeadersAsString()));

        logger.info(Arrays.equals(mBisReqBody.getBytes(), mReqBody.getBytes()));

        logger.info("_debug compare receive");
        logger.info(Arrays.equals(mResBody.getBytes(), mBisResBody.getBytes()));
    }
}
