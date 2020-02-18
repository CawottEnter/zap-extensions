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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;

public class HistoryReferenceSerializer implements Serializable {
    private static final Logger logger = Logger.getLogger(HistoryReferenceSerializer.class);
    private static final long serialVersionUID = 354054054055L;
    private int historyType;
    private Message message;
    private int id;

    public HistoryReferenceSerializer(HistoryReference reference) {
        id = reference.getHistoryId();
        this.historyType = reference.getHistoryType();
        try {
            this.message = new Message(reference);
        } catch (DatabaseException e) {
            e.printStackTrace();
        } catch (HttpMalformedHeaderException e) {
            e.printStackTrace();
        }
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public Message getMessage() {
        return message;
    }

    public void setMessage(Message message) {
        this.message = message;
    }

    public int getHistoryType() {
        return historyType;
    }

    public void setHistoryType(int historyType) {
        this.historyType = historyType;
    }

    public static final Comparator<HistoryReferenceSerializer> COMPARATOR =
            new Comparator<HistoryReferenceSerializer>() {
                @Override
                public int compare(HistoryReferenceSerializer o1, HistoryReferenceSerializer o2) {
                    return o1.getId() - o2.getId();
                }
            };

    public static final List<HistoryReferenceSerializer> convert(
            List<HistoryReference> references) {
        List<HistoryReferenceSerializer> list = new ArrayList<HistoryReferenceSerializer>();
        references.forEach(
                t -> {
                    list.add(new HistoryReferenceSerializer(t));
                });
        return list;
    }

    public void compare(HistoryReference reference) {
        logger.debug("_debug httphistory");
        logger.info("historyType" + (this.getHistoryType() == reference.getHistoryType()));
        logger.info("history id = " + (this.getId() == reference.getHistoryId()));
        try {
            this.getMessage().compare(reference.getHttpMessage());
        } catch (HttpMalformedHeaderException e) {
            e.printStackTrace();
        } catch (DatabaseException e) {
            e.printStackTrace();
        }
    }
}
