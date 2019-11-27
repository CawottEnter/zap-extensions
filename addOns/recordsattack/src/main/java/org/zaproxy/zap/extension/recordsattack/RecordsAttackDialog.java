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

import java.awt.Dimension;
import java.awt.Frame;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class RecordsAttackDialog extends StandardFieldsDialog {
    protected static final String[] LABELS = {
        "spiderajax.scandialog.tab.scope", "spiderajax.scandialog.tab.options",
        /*"spiderajax.scandialog.tab.elements"*/ };
    /** */
    private static final long serialVersionUID = 1L;

    private ExtensionRecordsAttack extension = null;
    private final ExtensionUserManagement extUserMgmt;

    RecordsAttackDialog(ExtensionRecordsAttack extension, Frame owner, Dimension dim) {
        super(owner, "spiderajax.scandialog.title", dim, LABELS);
        this.extension = extension;

        this.extUserMgmt =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionUserManagement.class);
    }

    @Override
    public void save() {
        this.extension.startRecord();
    }

    @Override
    public String validateFields() {
        // TODO Auto-generated method stub
        return null;
    }
}
