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
import java.util.List;
import org.zaproxy.zap.extension.recordsattack.ExtensionRecordsAttack;
import org.zaproxy.zap.extension.recordsattack.Scenario;

public class ScenarioSerializable implements Serializable {
    private String name;
    private String comments;
    private List<String> params;
    private List<HistoryReferenceSerializer> historyReference;
    private AuthentificationSerializable authentificationSerializable;
    private static final long serialVersionUID = 3520540540L;

    public ScenarioSerializable(
            String name,
            String comments,
            List<String> params,
            AuthentificationSerializable authentificationSerializable,
            List<HistoryReferenceSerializer> historyReference) {
        this.name = name;
        this.comments = comments;
        this.params = params;
        this.authentificationSerializable = authentificationSerializable;
        this.historyReference = historyReference;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getComments() {
        return comments;
    }

    public void setComments(String comments) {
        this.comments = comments;
    }

    public List<String> getParams() {
        return params;
    }

    public void setParams(List<String> params) {
        this.params = params;
    }

    public List<HistoryReferenceSerializer> getHistoryReference() {
        return historyReference;
    }

    public void setHistoryReference(List<HistoryReferenceSerializer> historyReference) {
        this.historyReference = historyReference;
    }

    public AuthentificationSerializable getAuthentificationSerializable() {
        return authentificationSerializable;
    }

    public void setAuthentificationSerializable(
            AuthentificationSerializable authentificationSerializable) {
        this.authentificationSerializable = authentificationSerializable;
    }

    public Scenario toScenario(ExtensionRecordsAttack extension) {
        return new Scenario(this, extension);
    }

    @Override
    public String toString() {
        return this.name;
    }
}
