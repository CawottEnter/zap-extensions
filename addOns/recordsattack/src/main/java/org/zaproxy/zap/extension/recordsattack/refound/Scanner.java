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
package org.zaproxy.zap.extension.recordsattack.refound;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.Vector;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;

public abstract class Scanner {
    private static final Logger logger = Logger.getLogger(Scanner.class);

    public int getId() {
        // TODO Auto-generated method stub
        return 0;
    }

    public String getName() {
        // TODO Auto-generated method stub
        return null;
    }

    public String getDescription() {
        // TODO Auto-generated method stub
        return null;
    }

    public void scan() {
        // TODO Auto-generated method stub

    }

    public int getCategory() {
        // TODO Auto-generated method stub
        return 0;
    }

    public String getSolution() {
        // TODO Auto-generated method stub
        return null;
    }

    public String getReference() {
        // TODO Auto-generated method stub
        return null;
    }

    public void notifyPluginCompleted(HostProcess parent) {
        // TODO Auto-generated method stub

    }

    /**
     * Plugin method that need to be implemented for the specific test. The passed message is a copy
     * which maintains only the Request's information so if the plugin need to manage the original
     * Response body a getBaseMsg() call should be done. the param name and the value are the
     * original value retrieved by the crawler and the current applied Variant.
     *
     * @param msg a copy of the HTTP message currently under scanning
     * @param param the name of the parameter under testing
     * @param value the clean value (no escaping is needed)
     */
    public abstract void scan(HttpMessage msg, String param, String value);

    public void setParameter(HttpMessage message, String param, String value) {
        if (getParamNames(message).contains(param)) {
            message.setNote("On va essayer de modifier le parametre :" + param);
            searchParamInUrlAndModify(message, param, value);
            searchParamInBodyAndModify(message, param);
        }
    }

    /*
     * TODO refaire avec une regex style replace
     */
    private void searchParamInUrlAndModify(HttpMessage message, String param, String value) {
        URI uri = message.getRequestHeader().getURI();
        List<String> accu = new ArrayList<String>();
        String[] paths = uri.toString().split("\\?");
        if (paths.length > 1) {
            accu.add(paths[0] + "?");
            paths = paths[1].split("&");
        } else return;
        int acc = 0;
        while (acc < paths.length) {
            if (paths[acc].split("=")[0].equalsIgnoreCase(param)) {
                paths[acc] = param + "=" + value;
            }
            acc++;
        }
        for (String s : paths) {
            accu.add("&" + s);
        }
        try {
            URI newURI = new URI(String.join("", accu), true);
            message.getRequestHeader().setURI(newURI);
            logger.info("new url :" + message.getRequestHeader().getURI());
            logger.info("new url :" + message.getRequestHeader().getURI());
            logger.info("new url :" + message.getRequestHeader().getURI());
            logger.info("new url :" + message.getRequestHeader().getURI());
            logger.info("new url :" + message.getRequestHeader().getURI());

        } catch (URIException | NullPointerException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @SuppressWarnings("unchecked")
    private void searchParamInBodyAndModify(HttpMessage message, String param) {
        TreeSet<HtmlParameter> parameters = message.getFormParams();
        TreeSet<HtmlParameter> cloned_set = new TreeSet<HtmlParameter>();
        cloned_set = (TreeSet<HtmlParameter>) parameters.clone();
        for (HtmlParameter p : cloned_set) {
            if (p.getName().equalsIgnoreCase(param)) {
                HtmlParameter newParam = new HtmlParameter(HtmlParameter.Type.form, param, "toto");
                parameters.remove(p);
                parameters.add(newParam);
            }
        }
        message.setFormParams(parameters);
    }

    // ZAP: Added getParamNames
    public Vector<String> getParamNames(HttpMessage message) {
        Vector<String> v = new Vector<>();
        // Get the params names from the query
        SortedSet<String> pns = message.getParamNameSet(HtmlParameter.Type.url);
        Iterator<String> iterator = pns.iterator();
        while (iterator.hasNext()) {
            String name = iterator.next();
            if (name != null) {
                v.add(name);
            }
        }

        // Get the param names from the POST
        pns = message.getParamNameSet(HtmlParameter.Type.form);
        iterator = pns.iterator();
        while (iterator.hasNext()) {
            String name = iterator.next();
            if (name != null) {
                v.add(name);
            }
        }
        return v;
    }

    /**
     * Encode the parameter value for a correct URL introduction
     *
     * @param value the value that need to be encoded
     * @return the Encoded value
     */
    private String getEscapedValue(String value) {

        if (value != null) {

            try {

                return URLEncoder.encode(value, "UTF-8");

            } catch (UnsupportedEncodingException ex) {

            }
        }

        return "";
    }
}
