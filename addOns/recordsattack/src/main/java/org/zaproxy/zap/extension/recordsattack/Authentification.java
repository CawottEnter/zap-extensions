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

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.parosproxy.paros.model.HistoryReference;

public class Authentification {
    private static final AtomicInteger count = new AtomicInteger(0);
    private String name;
    private String description;
    private List<HistoryReference> references;
    private int id;

    public Authentification(
            String nameAuthentification,
            String descriptionAuthentification,
            List<HistoryReference> references) {
        this.setName(nameAuthentification);
        this.setDescription(descriptionAuthentification);
        this.setReferences(references);
        this.id = count.incrementAndGet();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<HistoryReference> getReferences() {
        return references;
    }

    public void setReferences(List<HistoryReference> references) {
        this.references = references;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }
}
