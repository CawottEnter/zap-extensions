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
package org.zaproxy.zap.extension.recordsattack;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.openqa.selenium.*;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.remote.CapabilityType;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.httpsessions.HttpSession;
import org.zaproxy.zap.extension.httpsessions.HttpSessionTokensSet;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.SeleniumOptions;

public class SeleniumUsage {
    private WebDriver webDriver;
    private static final Logger logger = Logger.getLogger(SeleniumUsage.class);
    private Authentification authentification;

    public SeleniumUsage(Authentification authentification) {
        this.authentification = authentification;
    }

    public WebDriver get() {
        logger.debug("Setting up a Browser");
        if (webDriver == null)
            webDriver =
                    getWebDriverImpl(
                            HttpSender.AJAX_SPIDER_INITIATOR, Browser.FIREFOX, "127.0.0.1", 8080);
        return webDriver;
    }

    public WebDriver getWebDriverImpl(
            int requester, Browser browser, String proxyAddress, int proxyPort) {
        switch (browser) {
            case FIREFOX:
                FirefoxOptions firefoxOptions = new FirefoxOptions();
                setCommonOptions(firefoxOptions, proxyAddress, proxyPort);
                String geckoDriver =
                        System.getProperty(SeleniumOptions.FIREFOX_DRIVER_SYSTEM_PROPERTY);
                firefoxOptions.setLegacy(geckoDriver == null || geckoDriver.isEmpty());
                String binaryPath =
                        System.getProperty(SeleniumOptions.FIREFOX_BINARY_SYSTEM_PROPERTY);

                if (binaryPath != null && !binaryPath.isEmpty()) {

                    firefoxOptions.setBinary(binaryPath);
                }
                // Keep proxying localhost on Firefox >= 67

                firefoxOptions.addPreference("network.proxy.allow_hijacking_localhost", true);

                // Ensure ServiceWorkers are enabled for the HUD.

                firefoxOptions.addPreference("dom.serviceWorkers.enabled", true);

                // Disable the captive checks/requests, mainly to avoid flooding

                // the AJAX Spider results (those requests are out of scope) but

                // also useful for other launched browsers.

                firefoxOptions.addPreference("network.captive-portal-service.enabled", false);
                firefoxOptions.setHeadless(false);
                return new FirefoxDriver(firefoxOptions);
            default:
                throw new IllegalArgumentException("Unknown browser: " + browser);
        }
    }

    private static void setCommonOptions(
            MutableCapabilities capabilities, String proxyAddress, int proxyPort) {
        capabilities.setCapability(CapabilityType.ACCEPT_SSL_CERTS, true);
        // W3C capability
        capabilities.setCapability(CapabilityType.ACCEPT_INSECURE_CERTS, true);

        if (proxyAddress != null) {
            String httpProxy = proxyAddress + ":" + proxyPort;
            Proxy proxy = new Proxy();
            proxy.setHttpProxy(httpProxy);
            proxy.setSslProxy(httpProxy);
            capabilities.setCapability(CapabilityType.PROXY, proxy);
        }
    }

    public void executeJS(String jsCode) {

        JavascriptExecutor js = (JavascriptExecutor) this.webDriver;
        js.executeScript("alert('" + jsCode + "');");
    }

    public void _executeJS() {
        String jsScript =
                "var xhr = new XMLHttpRequest();\n"
                        + "xhr.onreadystatechange = function() {\n"
                        + "    if (xhr.readyState === 4){\n"
                        + "        document.getElementById('result').innerHTML = xhr.responseText;\n"
                        + "    }\n"
                        + "};\n"
                        + "function wait(ms){\n"
                        + "   var start = new Date().getTime();\n"
                        + "   var end = start;\n"
                        + "   while(end < start + ms) {\n"
                        + "     end = new Date().getTime();\n"
                        + "  }\n"
                        + "}"
                        + "wait(5000);  //7 seconds in milliseconds"
                        + "xhr.open('POST', 'http://sapdcy2.in.ac-rennes.fr/portailgest/portal/administrercyclades/__pmall_edit/__rpall_sousactivite/ADMINISTRER0x1CYCLADES?OngletID=1579267860438');\n"
                        + "xhr.send();";

        JavascriptExecutor js = (JavascriptExecutor) this.webDriver;
        js.executeScript(jsScript);
    }

    public void goTo(String uri,String method, List<HtmlParameter> parameter) {
        String forms= "var s = window.document.createElement('form');" +
                "s.src='alert(1)"
                + "window.document.head(s)";
        // TreeSet<HtmlParameter> cookie = request.getCookieParams();
        // HttpRequestBody bodyRequest =request.getRequestBody();
        _executeJS();
    }

    protected void authentification() {
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
                String method = reference.getMethod();
                String uri = reference.getURI().getURI();
                logger.info("DEBBUGING FROM SELENIUM :");
                logger.info("URI = " + uri);
                logger.info("METHOD IS : " + method);
                ArrayList<HtmlParameter> paramsPost = parse(message.getRequestBody().toString());
                paramsPost.forEach(
                        t -> {
                            logger.info("param is :" + t.getName() + " value : " + t.getValue());
                        });
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public Authentification getAuthentification() {
        return authentification;
    }

    public void setAuthentification(Authentification authentification) {
        this.authentification = authentification;
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
