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
import java.net.HttpCookie;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.httpsessions.HttpSession;
import org.zaproxy.zap.extension.httpsessions.HttpSessionTokensSet;
import org.zaproxy.zap.extension.recordsattack.Authentification;
import org.zaproxy.zap.network.HttpRequestBody;

public abstract class Scanner {
    private static final Logger logger = Logger.getLogger(Scanner.class);

    protected HttpSender httpSender;
    private Authentification authentification;
    private String id_session;

    private String[] kkeyValue;

    Scanner(Authentification authentification, String id_session, HttpSender httpSender) {
        this.authentification = authentification;
        this.id_session = id_session;
        this.httpSender = httpSender;
    }

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
    public abstract void scan(List<HistoryReference> historyReference, String parameters);

    public void setParameter(HttpMessage message, String param, String value) {
        if (getParamNames(message).contains(param)) {
            String note = message.getNote();
            message.setNote(note + "\n On va essayer de modifier le parametre :" + param);
            searchParamInUrlAndModify(message, param, value);
            searchParamInBodyAndModify(message, param, value);
        }
    }

    protected TreeSet<HtmlParameter> authentification() {
        // TODO supprimer les debugs
        HttpSessionTokensSet tokenSet = new HttpSessionTokensSet();
        HttpSession session = new HttpSession("testSession", tokenSet);

        TreeSet<HtmlParameter> lastCookies = null;
        final String d_sessionID = "jsessionid";
        for (HistoryReference reference : this.getAuthentification().getReferences()) {
            HttpMessage message;

            try {
                message = reference.getHttpMessage();

                message.setHttpSession(session);
                List<HttpCookie> nullCookies = new ArrayList<HttpCookie>();

                if (lastCookies == null) message.setCookies(nullCookies);
                else message.setCookieParams(lastCookies);
                Pattern p = Pattern.compile("jsessionid=.*\\?");
                Matcher matcher = p.matcher(message.getRequestHeader().getURI().getURI());
                if (matcher.find()) {
                    @SuppressWarnings("deprecation")
                    URI newUrl =
                            new URI(matcher.replaceFirst(d_sessionID + "=" + id_session + "?"));
                    HttpRequestHeader reqHeader = message.getRequestHeader();
                    HttpRequestBody reqBody = message.getRequestBody();
                    reqHeader.setURI(newUrl);

                    message = new HttpMessage(reqHeader, reqBody);
                }
                httpSender.sendAndReceive(message, true);
                lastCookies = message.getCookieParams();
                ExtensionHistory extHistory =
                        ((ExtensionHistory)
                                Control.getSingleton()
                                        .getExtensionLoader()
                                        .getExtension(ExtensionHistory.NAME));
                extHistory.addHistory(message, HistoryReference.TYPE_PROXIED);
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        return lastCookies;
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
        /*
                logger.info("avant recuperation du message :" + message.getRequestBody().toString());
                logger.info("Avant, tete du nouveau truc: ");

                getParamsFromRequest(message, HtmlParameter.Type.form)
                        .forEach(t -> logger.info(t.getName() + ":" + t.getValue()));
        */
        ArrayList<HtmlParameter> parameters = parse(message.getRequestBody().toString());
        /*
        getParamsFromRequest(message, HtmlParameter.Type.form);
        */
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

    public ArrayList<HtmlParameter> getParamsFromRequest(HttpMessage msg, HtmlParameter.Type type) {
        Map<String, String> paramMap = Model.getSingleton().getSession().getParams(msg, type);
        ArrayList<HtmlParameter> htmlParameters = new ArrayList<HtmlParameter>();
        for (Map.Entry<String, String> p : paramMap.entrySet()) {
            htmlParameters.add(new HtmlParameter(type, p.getKey(), p.getValue()));
        }
        return htmlParameters;
    }

    public ArrayList<HtmlParameter> parse(String paramStr) {

        ArrayList<HtmlParameter> htmlParameters = new ArrayList<HtmlParameter>();
        String KeyValuePairSeparators = "&";
        String KeyValueSeparators = "=";
        Pattern KeyValueSeparatorPattern = (Pattern.compile("[" + KeyValuePairSeparators + "]"));
        if (paramStr != null) {

            String[] keyValue = KeyValueSeparatorPattern.split(paramStr);

            for (String s : keyValue) {

                try {

                    String[] keyEqValue = KeyValueSeparatorPattern.split(s);

                    if (keyEqValue.length == 1) {
                        //   htmlParameters.add(new HtmlParameter(HtmlParameter.Type.form,
                        // p.getKey(),
                        String[] kkeyValue = keyEqValue[0].split("=");

                        htmlParameters.add(
                                new HtmlParameter(
                                        HtmlParameter.Type.form,
                                        kkeyValue[0],
                                        (kkeyValue.length > 1) ? kkeyValue[1] : ""));
                        /*
                        logger.info("keyEqValue.length == 1");
                        logger.info("keyEqValue = " + keyEqValue[0]);
                        logger.info("KeyValue : " + s);
                        */

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
    /*
        public ArrayList<HtmlParameter> getParamsFromRequest2(
                HttpMessage msg, HtmlParameter.Type type) {}
    */
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

    public abstract boolean isFinish();

    public Authentification getAuthentification() {
        return authentification;
    }

    public void setAuthentification(Authentification authentification) {
        this.authentification = authentification;
    }
}
