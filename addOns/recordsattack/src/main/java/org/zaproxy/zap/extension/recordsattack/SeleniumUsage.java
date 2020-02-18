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
import java.util.*;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.openqa.selenium.*;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.remote.CapabilityType;
import org.parosproxy.paros.network.*;
import org.zaproxy.zap.extension.recordsattack.serializableHelper.AuthentificationSerializable;
import org.zaproxy.zap.extension.recordsattack.serializableHelper.HistoryReferenceSerializer;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.SeleniumOptions;

public class SeleniumUsage implements Observer {
    private WebDriver webDriver;
    private static final Logger logger = Logger.getLogger(SeleniumUsage.class);
    // private Authentification authentification;
    private AuthentificationSerializable authentificationSerializable;
    private ExtensionRecordsAttack extension;
    private ProxySeleniumListener proxySeleniumListener;
    private List<HistoryReferenceSerializer> references;

    public SeleniumUsage(
            AuthentificationSerializable authentification, ExtensionRecordsAttack extension) {
        this.extension = extension;
        authentificationSerializable = authentification;
        this.proxySeleniumListener = this.extension.getProxySeleniumListener();
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

    // @TODO implementation des autres Mehtode GET POST PUT DELETE etc.
    public void _executeJS(HttpMessage httpMessage) {
        StringBuilder builder = new StringBuilder();
        if (isXMLHttpRequest(httpMessage)) {
            builder.append("var requestRecordsXHR = new XMLHttpRequest();\n");
            if (httpMessage.getRequestHeader().getMethod().equals("POST")) {
                try {
                    builder.append(
                            "requestRecordsXHR.open('POST','"
                                    + httpMessage.getRequestHeader().getURI().getPath()
                                    + "');\n");
                    List<HtmlParameter> paramsPost = parse(httpMessage.getRequestBody().toString());
                    StringBuilder builderOfPost = new StringBuilder();
                    if (paramsPost.size() > 0)
                        builderOfPost.append(
                                paramsPost.get(0).getName() + "=" + paramsPost.get(0).getValue());
                    for (int i = 1; i < paramsPost.size(); i++) {
                        builderOfPost.append(
                                "&"
                                        + paramsPost.get(i).getName()
                                        + "="
                                        + paramsPost.get(i).getValue());
                    }
                    builder.append("requestRecordsXHR.send('" + builderOfPost.toString() + "');\n");
                    int _acc = 0;
                    while (_acc < 10) {
                        logger.info("XHR POST");
                        _acc++;
                    }
                } catch (URIException e) {
                    e.printStackTrace();
                }

            } else {
                try {
                    builder.append(
                            "requestRecordsXHR.open('GET','"
                                    + httpMessage.getRequestHeader().getURI().getPath()
                                    + "');\n");
                    int _acc = 0;
                    while (_acc < 10) {
                        logger.info("XHR FOCK UN GET");
                        _acc++;
                    }
                } catch (URIException e) {
                    e.printStackTrace();
                }
                builder.append("requestRecordsXHR.send();\n");
            }
            try {
                logger.info("Le build : " + builder.toString());

                Thread.sleep(10000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            JavascriptExecutor js = (JavascriptExecutor) this.webDriver;

            js.executeScript(builder.toString());
        } else {
            logger.info("_debug 1 " + httpMessage.getRequestHeader().getURI().getEscapedQuery());
            try {
                logger.info(
                        "_debug 2 " + httpMessage.getRequestHeader().getURI().getPath().toString());
                logger.info("_debug 3 " + httpMessage.getRequestHeader().getURI().getScheme());

            } catch (URIException e) {
                e.printStackTrace();
            }

            if (httpMessage.getRequestHeader().getMethod().equals("POST")) {

                ArrayList<HtmlParameter> paramsPost =
                        parse(httpMessage.getRequestBody().toString());
                builder.append("var f = document.createElement('FORM');\n");
                builder.append("f.method='POST';\n");
                builder.append("f.id='recordsattackForms';\n");
                try {
                    builder.append(
                            "f.action=\""
                                    + httpMessage.getRequestHeader().getURI().getPath()
                                    + "?"
                                    + httpMessage.getRequestHeader().getURI().getEscapedQuery()
                                    + "\";\n");
                } catch (URIException e) {
                    e.printStackTrace();
                }
                for (HtmlParameter param : paramsPost) {
                    builder.append("var i = document.createElement('input');\n");
                    builder.append("i.setAttribute('type','text');\n");
                    builder.append("i.setAttribute('name','" + param.getName() + "');\n");
                    builder.append("i.setAttribute('value','" + param.getValue() + "');\n");
                    builder.append("f.appendChild(i);\n");
                }
                builder.append("var s = document.createElement('input');\n");
                builder.append("s.setAttribute('type','submit');\n");
                builder.append("s.setAttribute('value','Submit');\n");
                builder.append("s.setAttribute('id','recordsattackID');\n");
                builder.append("f.appendChild(s);\n");
                builder.append("document.getElementsByTagName('body')[0].appendChild(f);\n");
                JavascriptExecutor js = (JavascriptExecutor) this.webDriver;
                js.executeScript(builder.toString());

                // js.executeScript("document.querySelector('#validerProfilButton').click();\n");
                js.executeScript("document.querySelector('#recordsattackID').click();\n");

            } else if (httpMessage.getRequestHeader().getMethod().equals("GET")) {
                {
                    logger.info("_debug method GET");
                    builder.append("var f = document.createElement('FORM');\n");
                    builder.append("f.method='GET';\n");
                    // builder.append("f.id='recordsattackID';\n");

                    try {
                        logger.info(
                                "_debug get : "
                                        + httpMessage.getRequestHeader().getURI().getPath());
                        logger.info(
                                "_debug get : "
                                        + httpMessage
                                                .getRequestHeader()
                                                .getURI()
                                                .getEscapedQuery());
                        logger.info(
                                "_debug2 get : "
                                        + (httpMessage.getRequestHeader().getURI().getQuery()
                                                == null));
                        if (httpMessage.getRequestHeader().getURI().getQuery() != null
                                && !httpMessage.getRequestHeader().getURI().getQuery().isEmpty()) {
                            ArrayList<HtmlParameter> paramsGet =
                                    parse(httpMessage.getRequestHeader().getURI().getQuery());
                            for (HtmlParameter param : paramsGet) {
                                builder.append("var i = document.createElement('input');\n");
                                builder.append("i.setAttribute('type','text');\n");
                                builder.append(
                                        "i.setAttribute('name','" + param.getName() + "');\n");
                                builder.append(
                                        "i.setAttribute('value','" + param.getValue() + "');\n");
                                builder.append("f.appendChild(i);\n");
                            }
                        }

                        builder.append(
                                "f.action=\""
                                        + httpMessage.getRequestHeader().getURI().getPath()
                                        + "\";\n");
                    } catch (URIException e) {
                        e.printStackTrace();
                    }
                    builder.append("var s = document.createElement('input');\n");
                    builder.append("s.setAttribute('type','submit');\n");
                    builder.append("s.setAttribute('value','Submit');\n");
                    builder.append("s.setAttribute('id','recordsattackID');\n");
                    builder.append("f.appendChild(s);\n");
                    builder.append("document.getElementsByTagName('body')[0].appendChild(f);\n");
                    JavascriptExecutor js = (JavascriptExecutor) this.webDriver;

                    js.executeScript(builder.toString());
                    js.executeScript("document.querySelector('#recordsattackID').click();\n");
                }
            }
        }
    }

    private String getTag() {
        WebElement csrfToken = this.webDriver.findElement(By.name(("_csrf")));
        String csrf = csrfToken.getText();
        return csrf;
    }

    @Override
    public void update(Observable observable, Object o) {
        logger.info("Je suis notifie");
        if (o instanceof HttpMessage) {
            HttpMessage message = (HttpMessage) o;
            HttpResponseHeader responseHeader = message.getResponseHeader();
            if (responseHeader.getStatusCode() == 0) // is a request not a reponse
            {
                logger.info("Status is 0 ");
            } else {
                logger.info("status is 1");
                // @todo a supprimer maybe
                // receiveResponse();
            }
        }
    }

    public void receiveResponse() {
        HistoryReferenceSerializer reference = references.remove(0);
        HttpMessage message = reference.getMessage().toHttpMessage();

        logger.info("Receive and response");
        logger.info("size of stack is : " + references.size());

        _executeJS(message);
    }

    public void addObserver() {
        this.proxySeleniumListener.addObserver(this);
    }

    public void removeObserver() {
        this.proxySeleniumListener.removeObserver(this);
    }

    public void resetSelenium() {
        try {
            logger.info("Reset de la session Selenium");
            Thread.sleep(4000);
            this.webDriver.close();

        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void authentification() {
        references = new ArrayList<HistoryReferenceSerializer>();
        this.get();
        references.addAll(this.authentificationSerializable.getReferenceSerializers());
        logger.info("GOTOOOOOOOOOOOOOOO");

        if (!references.isEmpty()) {
            logger.info("GOTOOOOOOOOOOOOOOO");
            HistoryReferenceSerializer firstReference = references.remove(0);
            HttpMessage message = firstReference.getMessage().toHttpMessage();
            try {
                logger.info("go to the : " + message.getRequestHeader().getURI().toString());
                this.webDriver.get(message.getRequestHeader().getURI().toString());
                message = references.remove(0).getMessage().toHttpMessage();
                JavascriptExecutor js = (JavascriptExecutor) this.webDriver;
                js.executeScript("document.querySelector('#validerProfilButton').click();\n");
                Thread.sleep(2000);

                // this.proxySeleniumListener.startIntercept();

            } catch (Exception e) {
                e.printStackTrace();
                logger.info(e.getMessage());
                logger.info(e.getCause());
            }
        }
        logger.info("Size of references : " + references.size());
    }

    private boolean waitFinish() {
        while (!references.isEmpty()) {
            continue;
        }
        return true;
    }

    /*
    protected void authentification() {
        this.proxySeleniumListener.addObserver(this);
        // TODO supprimer les debugs
        HttpSessionTokensSet tokenSet = new HttpSessionTokensSet();
        HttpSession session = new HttpSession("testSession", tokenSet);

        TreeSet<HtmlParameter> lastCookies = null;
        final String d_sessionID = "jsessionid";
        List<HistoryReference> references = this.getAuthentification().getReferences();
        if (references.size() > 0) {
            try {
                HttpMessage message = references.get(0).getHttpMessage();
                logger.info("Try to go first authentification url");
                this.proxySeleniumListener.startIntercept();
                this.webDriver.get(message.getRequestHeader().getURI().toString());


                // this.webDriver.wait(10);
                this._executeJS(references.get(1).getHttpMessage());
            } catch (Exception e) {
                e.printStackTrace();
                logger.info("error is : " + e.getMessage());
                logger.info("error is : " + e.getCause());
            }
        }
        for (int i = 1; i < references.size(); i++) {
            HistoryReference reference = references.get(i);
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


     */

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

    // @TODO modifier l'endroit de cette methode elle n'a rien a foutre là
    public boolean isXMLHttpRequest(HttpMessage message) {
        for (HttpHeaderField t : message.getRequestHeader().getHeaders()) {
            if (t.getName().equals("X-Requested-With") && t.getValue().equals("XMLHttpRequest"))
                return true;
        }
        return false;
    }
}
