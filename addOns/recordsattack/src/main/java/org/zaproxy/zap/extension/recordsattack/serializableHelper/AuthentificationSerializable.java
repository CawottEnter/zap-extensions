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
import org.parosproxy.paros.model.HistoryReference;

public class AuthentificationSerializable implements Serializable {
    private static final long serialVersionUID = 3540540540L;

    private String name;
    private String description;
    private int id;
    private List<HistoryReferenceSerializer> referenceSerializers;

    public AuthentificationSerializable(
            String name, String description, int id, List<HistoryReference> references) {
        this.name = name;
        this.description = description;
        this.id = id;
        this.referenceSerializers = HistoryReferenceSerializer.convert(references);
    }

    public List<HistoryReferenceSerializer> getReferenceSerializers() {
        return referenceSerializers;
    }

    public void setReferenceSerializers(List<HistoryReferenceSerializer> referenceSerializers) {
        this.referenceSerializers = referenceSerializers;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
