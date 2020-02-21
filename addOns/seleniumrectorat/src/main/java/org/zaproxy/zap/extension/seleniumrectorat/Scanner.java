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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.network.HttpRequestBody;

public class Scanner {
    private static final Logger logger = Logger.getLogger(Scanner.class);

    public void setParameter(HttpMessage message, String param, String value) {
        getParamNames(message)
                .forEach(
                        t -> {
                            logger.info("param trouve : " + t);
                        });
        if (getParamNames(message).contains(param)) {
            logger.info("_debug");
            String note = message.getNote();
            byte[] toto = message.getRequestBody().getBytes();
            logger.info(message.getRequestBody().toString());
            message.setNote(note + "\n On va essayer de modifier le parametre :" + param);
            searchParamInUrlAndModify(message, param, value);
            searchParamInBodyAndModify(message, param, value);
            logger.info("_debug2");
            logger.info(message.getRequestBody().toString());

            getParamNames(message)
                    .forEach(
                            t -> {
                                logger.info("param Apres trouve : " + t);
                            });
            logger.info("see the request :");
            logger.info(message.getRequestBody().getBytes());
            message.setRequestBody(toto);
            logger.info("see the request :");
            logger.info(message.getRequestBody().toString());
            String helppp = new String(toto);
            String tiff = helppp;
            helppp = helppp.replace("test", "tes");
            HttpRequestBody body = new HttpRequestBody(helppp);

            message.setRequestBody(body);
            // message.setRequestBody(helppp.getBytes());
            /*String s = Base64.getEncoder().encodeToString(bytes);*/
        }
    }

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
                paths[acc] = param + "=" + getEscapedValue(value);
            }
            acc++;
        }
        for (String s : paths) {
            accu.add("&" + s);
        }
        try {
            String parameters = String.join("", accu);
            URI newURI = new URI(parameters, true);
            message.getRequestHeader().setURI(newURI);
        } catch (URIException | NullPointerException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @SuppressWarnings("unchecked")
    private void searchParamInBodyAndModify(HttpMessage message, String param, String value) {
        ArrayList<HtmlParameter> parameters = parse(message.getRequestBody().toString());
        ArrayList<HtmlParameter> cloned_set = new ArrayList<HtmlParameter>();
        cloned_set = (ArrayList<HtmlParameter>) parameters.clone();

        for (HtmlParameter p : cloned_set) {

            if (p.getName().equalsIgnoreCase(param)) {
                logger.info("trouveeee :) ");
                String note = message.getNote();
                message.setNote(note + "\n trouve parametre : " + param);
                HtmlParameter newParam = new HtmlParameter(HtmlParameter.Type.form, param, value);
                parameters.remove(p);
                parameters.add(newParam);
            }
        }

        setParamsFromRequest(parameters, message);
    }

    public List<String> searchValueInRequest(HttpMessage message, String value) {
        List<String> parametersWithValue = new ArrayList<>();
        for (HttpHeaderField httpHeaderField : message.getRequestHeader().getHeaders()) {
            if (httpHeaderField.getValue().equals(value))
                parametersWithValue.add(httpHeaderField.getName());
        }
        ArrayList<HtmlParameter> parameters = parse(message.getRequestBody().toString());
        for (HtmlParameter t : parameters) {
            if (t.getValue().equals(value)) parametersWithValue.add(t.getName());
        }
        return parametersWithValue;
    }

    public ArrayList<HtmlParameter> parse(String paramStr) {
        ArrayList<org.parosproxy.paros.network.HtmlParameter> htmlParameters =
                new ArrayList<org.parosproxy.paros.network.HtmlParameter>();
        String KeyValuePairSeparators = "&";
        String KeyValueSeparators = "=";
        Pattern KeyValueSeparatorPattern = (Pattern.compile("[" + KeyValuePairSeparators + "]"));
        if (paramStr != null) {
            String[] keyValue = KeyValueSeparatorPattern.split(paramStr);
            for (String s : keyValue) {
                try {
                    String[] keyEqValue = KeyValueSeparatorPattern.split(s);
                    if (keyEqValue.length == 1) {
                        String[] kkeyValue = keyEqValue[0].split("=");
                        htmlParameters.add(
                                new org.parosproxy.paros.network.HtmlParameter(
                                        org.parosproxy.paros.network.HtmlParameter.Type.form,
                                        kkeyValue[0],
                                        (kkeyValue.length > 1) ? kkeyValue[1] : ""));

                    } else if (keyEqValue.length > 1) {
                        /*
                        logger.info("keyEqValue.length > 1");
                        logger.info("keyEqValue = " + keyEqValue[0]);
                        logger.info(" keyEqValue[1] = " + keyEqValue[1]);
                        */
                    }

                } catch (Exception e) {
                    logger.error(e.getMessage(), e);
                }
            }
        }

        return htmlParameters;
    }

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

    private String getEscapedValue(String value) {
        if (value != null) {
            try {
                return URLEncoder.encode(value, "UTF-8");
            } catch (UnsupportedEncodingException ex) {
            }
        }
        return "";
    }

    public void setParamsFromRequest(List<HtmlParameter> newparams, HttpMessage msg) {
        if (newparams.isEmpty()) {
            msg.getRequestBody().setBody("");
            return;
        }
        StringBuilder postData = new StringBuilder();
        for (HtmlParameter param : newparams) {
            postData.append(param.getName());
            postData.append("=");
            postData.append(param.getValue());
            postData.append("&");
        }
        String data = "";
        if (postData.length() != 0) {
            data = postData.substring(0, postData.length() - 1);
        }
        msg.getRequestBody().setBody(data);
    }
}
