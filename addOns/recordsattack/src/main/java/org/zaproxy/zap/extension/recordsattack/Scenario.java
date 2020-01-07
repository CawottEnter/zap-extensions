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

import java.net.HttpCookie;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Scanner;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.httpsessions.HttpSession;
import org.zaproxy.zap.extension.httpsessions.HttpSessionTokensSet;
import org.zaproxy.zap.extension.recordsattack.refound.BufferOverflow;
import org.zaproxy.zap.network.HttpRequestBody;

public class Scenario {
    private static final Logger logger = Logger.getLogger(Scenario.class);
    private String name;
    private String comments;
    private Authentification authentification;
    private List<String> params;
    private List<HistoryReference> historyReference;
    private HttpSender httpSender;
    private String id_session;

    Scenario(
            String name,
            String comments,
            List<String> paramsSelected,
            List<HistoryReference> references,
            Authentification authentification) {
        this.name = name;
        this.comments = comments;
        this.params = paramsSelected;
        this.historyReference = references;
        this.authentification = authentification;
        httpSender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(),
                        true,
                        HttpSender.MANUAL_REQUEST_INITIATOR);
    }

    public void replayScenario() {
	/*
	 * On recupere les differents types d attaques selectionner par l utilisateur
	 * Tant que le scanner ne dit pas de passer au scanner suivant, on rejoue l authentification et le scenario avec la nouvelle attaque
	 *
	 */
	//TODO


        for (String p : params) {
            boolean newtScanner = false;
            
            TreeSet<HtmlParameter> cookies = authentification();

            for (HistoryReference reference : historyReference) {
                try {
                    logger.info("reference id : " + reference.getHistoryId());
                    HttpMessage message = reference.getHttpMessage();
                    String payload = "toto";
                    HttpMessage sourceMsg2 = message.cloneRequest();
                    sourceMsg2.setCookieParams(cookies);
                    sendRequest(sourceMsg2, p, payload);
                    cookies = sourceMsg2.getCookieParams();
                } catch (HttpMalformedHeaderException
                        | DatabaseException e) { // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }
    }

    private TreeSet<HtmlParameter> authentification() {
        // TODO supprimer les debugs
        HttpSessionTokensSet tokenSet = new HttpSessionTokensSet();
        HttpSession session = new HttpSession("testSession", tokenSet);

        TreeSet<HtmlParameter> lastCookies = null;
        final String d_sessionID = "jsessionid";
        for (HistoryReference reference : this.getAuthentification().getReferences()) {
            HttpMessage message;

            try {
                message = reference.getHttpMessage();
                HttpMessage sourceMsg2 = message.cloneRequest();
                sourceMsg2.setHttpSession(session);
                List<HttpCookie> nullCookies = new ArrayList<HttpCookie>();

                if (lastCookies == null) sourceMsg2.setCookies(nullCookies);
                else 
                    sourceMsg2.setCookieParams(lastCookies);
                Pattern p = Pattern.compile("jsessionid=.*\\?");
                Matcher matcher = p.matcher(sourceMsg2.getRequestHeader().getURI().getURI());
                if (matcher.find()) {
                    @SuppressWarnings("deprecation")
                    URI newUrl =
                            new URI(matcher.replaceFirst(d_sessionID + "=" + id_session + "?"));
                    HttpRequestHeader reqHeader = sourceMsg2.getRequestHeader();
                    HttpRequestBody reqBody = sourceMsg2.getRequestBody();
                    reqHeader.setURI(newUrl);

                    sourceMsg2 = new HttpMessage(reqHeader, reqBody);
                }

                httpSender.sendAndReceive(sourceMsg2, true);
                lastCookies = sourceMsg2.getCookieParams();
                ExtensionHistory extHistory =
                        ((ExtensionHistory)
                                Control.getSingleton()
                                        .getExtensionLoader()
                                        .getExtension(ExtensionHistory.NAME));
                extHistory.addHistory(sourceMsg2, HistoryReference.TYPE_PROXIED);
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        return lastCookies;
    }

    public void sendRequest(HttpMessage message, String param, String payload) {

        Injection injection = new Injection();
        injection.scan(message, param, payload);
    }

    public Authentification getAuthentification() {
        return authentification;
    }

    public void setAuthentification(Authentification authentification) {
        this.authentification = authentification;
    }
}
