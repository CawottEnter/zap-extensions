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
import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.recordsattack.refound.PersistentXSSAttack;
import org.zaproxy.zap.extension.recordsattack.refound.Scanner;
import org.zaproxy.zap.extension.recordsattack.serializableHelper.AuthentificationSerializable;
import org.zaproxy.zap.extension.recordsattack.serializableHelper.HistoryReferenceSerializer;
import org.zaproxy.zap.extension.recordsattack.serializableHelper.ScenarioSerializable;

public class Scenario {
    private ScenarioSerializable scenarioSerializable;
    private static final Logger logger = Logger.getLogger(Scenario.class);
    private ExtensionRecordsAttack extension;

    Scenario(
            String name,
            String comments,
            List<String> paramsSelected,
            List<HistoryReferenceSerializer> references,
            Authentification authentification,
            ExtensionRecordsAttack extension) {

        AuthentificationSerializable authentificationSerializable =
                new AuthentificationSerializable(
                        authentification.getName(),
                        authentification.getDescription(),
                        authentification.getId(),
                        authentification.getReferences());

        this.extension = extension;

        scenarioSerializable =
                new ScenarioSerializable(
                        name, comments, paramsSelected, authentificationSerializable, references);
    }

    public Scenario(ScenarioSerializable scenarioSerializable, ExtensionRecordsAttack extension) {
        this.extension = extension;
        this.scenarioSerializable = scenarioSerializable;
    }

    public void replayScenario() {
        this.extension.getProxyRecordsListener().stopRecord();
        /*
         * On recupere les differents types d attaques selectionner par l utilisateur
         * Tant que le scanner ne dit pas de passer au scanner suivant, on rejoue l authentification et le scenario avec la nouvelle attaque
         *
         */
        // TODO remplacer par liste des scanners
        for (int i = 0; i < 1; i++) {
            SeleniumUsage usage =
                    new SeleniumUsage(
                            this.getScenarioSerializable().getAuthentificationSerializable(),
                            this.extension);
            usage.get();

            // usage.authentification();
            for (String p : getParams()) {
                boolean newtScanner = false;
                boolean stop = false;

                Scanner PersistentXSS =
                        new PersistentXSSAttack(
                                this.getScenarioSerializable().getAuthentificationSerializable(),
                                usage);
                PersistentXSS.scan(this.getScenarioSerializable().getHistoryReference(), p);

                // oracle.scan(historyReference, p);
                // WebDriver webDriver = usage.get();

                // Scanner oracle = new PersistentXSSAttack(authentification, httpSender, usage);
                // oracle.scan(historyReference, p);
                //  logger.info("FINIIIIIIIIII");

                /*
                webDriver.get(
                        "http://sapdcy2.in.ac-rennes.fr/portailgest/portal/accueil?sso=O&employeeMail=julien.alexandre@ac-rennes.fr");
                try {
                    webDriver.wait(10000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                */
                /*
                int _acc = 0;
                while (_acc < 10) {
                    usage.authentification();
                    usage._executeJS();
                    _acc++;
                }
                // usage._executeJS();
                // usage.executeJS("hello");
                // usage.executeJS("Toto :)");
                /*
                                BrowserMobProxy proxy = new BrowserMobProxyServer();
                                proxy.setTrustAllServers(true);
                                proxy.start();
                                proxy.addRequestFilter(
                                        new RequestFilter() {
                                            @Override
                                            public HttpResponse filterRequest(
                                                    HttpRequest request,
                                                    HttpMessageContents contents,
                                                    HttpMessageInfo messageInfo) {
                                                logger.info("METHOD IS : " + request.getMethod());
                                                logger.info(
                                                        "SETTING METHOD : "
                                                                + request.setMethod(new HttpMethod("POST")));
                                                return null;
                                            }
                                        });
                                Proxy seleniumProxy = ClientUtil.createSeleniumProxy(proxy);

                                try {
                                    String hostIp = Inet4Address.getLocalHost().getHostAddress();
                                    seleniumProxy.setHttpProxy(hostIp + ":" + proxy.getPort());
                                    seleniumProxy.setSslProxy(hostIp + ":" + proxy.getPort());
                                } catch (UnknownHostException e) {
                                    e.printStackTrace();
                                    logger.info("erreur selenium :" + e.getMessage());
                                }
                                DesiredCapabilities capabilities = new DesiredCapabilities();
                                capabilities.setCapability(CapabilityType.PROXY, seleniumProxy);

                                System.setProperty("webdriver.chrome.driver", "drivers/chromedriver");
                                ChromeOptions options = new ChromeOptions();
                                options.merge(capabilities);
                                WebDriver driver = new ChromeDriver(options);
                                driver.get("http://www.google.co.in");
                */

                // BrowserMobProxy proxy = new BrowserMobProxyServer();
                /*

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
                */
            }
        }
    }
    /*
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
                else sourceMsg2.setCookieParams(lastCookies);
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
    /*
    public void sendRequest(HttpMessage message, String param, String payload) {

        Injection injection = new Injection();
        //  injection.scan(message, param, payload);
    }
    */

    public AuthentificationSerializable getAuthentification() {
        return this.getScenarioSerializable().getAuthentificationSerializable();
    }

    public void setAuthentification(AuthentificationSerializable authentification) {
        this.getScenarioSerializable().setAuthentificationSerializable(authentification);
    }

    public String getName() {
        return this.scenarioSerializable.getName();
    }

    /*
        public void setIdScenario(int idScenario) {
            this.idScenario = idScenario;
        }

        public int getIdScenario() {
            return idScenario;
        }
    */
    public String getComments() {
        return this.scenarioSerializable.getComments();
    }

    public List<String> getParams() {
        return this.scenarioSerializable.getParams();
    }

    public ScenarioSerializable getScenarioSerializable() {
        return scenarioSerializable;
    }
}
