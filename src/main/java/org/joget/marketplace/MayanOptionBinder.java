package org.joget.marketplace;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.http.HttpHeaders;
import org.apache.http.ParseException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.model.Element;
import org.joget.apps.form.model.FormBinder;
import org.joget.apps.form.model.FormData;
import org.joget.apps.form.model.FormLoadOptionsBinder;
import org.joget.apps.form.model.FormRow;
import org.joget.apps.form.model.FormRowSet;
import org.joget.apps.form.service.FormUtil;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.SecurityUtil;
import org.json.JSONArray;
import org.json.JSONObject;

public class MayanOptionBinder extends FormBinder implements FormLoadOptionsBinder {

    private static final String OPT_DOC_TYPES = "DOC_TYPES";
    private static final String OPT_CABINETS = "CABINETS";
    private static final String OPT_TAGS = "TAGS";

    @Override
    public FormRowSet load(Element element, String primaryKey, FormData formData) {
        FormRowSet results = new FormRowSet();
        results.setMultiRow(true);

        String options = getPropertyString("mayan_options");
        String serverUrl = getPropertyString("serverUrl");
        String username = getPropertyString("username");
        String password = getPropertyString("password");

        password = SecurityUtil.decrypt(password);

        if (serverUrl.endsWith("/")) {
            serverUrl = serverUrl.substring(0, serverUrl.length() - 1);
        }

        boolean formBuilderActive = FormUtil.isFormBuilderActive();

        if (!formBuilderActive) {
            if (OPT_CABINETS.equalsIgnoreCase(options)) {
                String url = serverUrl + "/api/v4/cabinets/?_ordering=label";
                CloseableHttpClient httpClient = HttpClients.createDefault();

                try {
                    HttpGet httpGet = new HttpGet(url);
                    String auth = username + ":" + password;
                    byte[] encodedAuth = java.util.Base64.getEncoder().encode(auth.getBytes());
                    String authHeader = "Basic " + new String(encodedAuth);
                    httpGet.setHeader(HttpHeaders.AUTHORIZATION, authHeader);
                    CloseableHttpResponse response = httpClient.execute(httpGet);
                    int statusCode = response.getStatusLine().getStatusCode();
                    if (statusCode == 200) { // HTTP 200 OK
                        // Parse and print the response content
                        String responseBody = EntityUtils.toString(response.getEntity());
                        JSONObject jSONObject = new JSONObject(responseBody);
                        JSONArray array = (JSONArray) jSONObject.get("results");

                        if ("true".equals(getPropertyString("addEmptyOption"))) {
                            FormRow emptyRow = new FormRow();
                            emptyRow.setProperty(FormUtil.PROPERTY_VALUE, "");
                            emptyRow.setProperty(FormUtil.PROPERTY_LABEL, getPropertyString("emptyLabel"));
                            results.add(emptyRow);
                        }

                        for (int i = 0; i < array.length(); i++) {
                            FormRow r = new FormRow();
                            JSONObject cabinet = (JSONObject) array.get(i);
                            int id = (int) cabinet.get("id");
                            String label = (String) cabinet.get("label");
                            if (cabinet.get("parent_id") != null) {
                                label = (String) cabinet.get("full_path");
                            }
                            r.setProperty(FormUtil.PROPERTY_VALUE, String.valueOf(id));
                            r.setProperty(FormUtil.PROPERTY_LABEL, label);
                            results.add(r);
                        }
                    } else {
                        System.err.println("HTTP Request failed with status code: " + statusCode);
                    }

                    // Ensure the response is closed properly
                    response.close();
                } catch (IOException | ParseException ex) {
                    LogUtil.error(getClassName(), ex, ex.getMessage());
                } finally {
                    try {
                        httpClient.close();
                    } catch (IOException ex) {
                        LogUtil.error(getClassName(), ex, ex.getMessage());
                    }
                }
            } else if (OPT_DOC_TYPES.equalsIgnoreCase(options)) {
                String url = serverUrl + "/api/v4/document_types/?_ordering=label";
                CloseableHttpClient httpClient = HttpClients.createDefault();

                try {
                    HttpGet httpGet = new HttpGet(url);
                    String auth = username + ":" + password;
                    byte[] encodedAuth = java.util.Base64.getEncoder().encode(auth.getBytes());
                    String authHeader = "Basic " + new String(encodedAuth);
                    httpGet.setHeader(HttpHeaders.AUTHORIZATION, authHeader);
                    CloseableHttpResponse response = httpClient.execute(httpGet);
                    int statusCode = response.getStatusLine().getStatusCode();
                    if (statusCode == 200) { // HTTP 200 OK
                        // Parse and print the response content
                        String responseBody = EntityUtils.toString(response.getEntity());
                        JSONObject jSONObject = new JSONObject(responseBody);
                        JSONArray array = (JSONArray) jSONObject.get("results");

                        if ("true".equals(getPropertyString("addEmptyOption"))) {
                            FormRow emptyRow = new FormRow();
                            emptyRow.setProperty(FormUtil.PROPERTY_VALUE, "");
                            emptyRow.setProperty(FormUtil.PROPERTY_LABEL, getPropertyString("emptyLabel"));
                            results.add(emptyRow);
                        }

                        for (int i = 0; i < array.length(); i++) {
                            FormRow r = new FormRow();
                            JSONObject cabinet = (JSONObject) array.get(i);
                            int id = (int) cabinet.get("id");
                            String label = (String) cabinet.get("label");

                            r.setProperty(FormUtil.PROPERTY_VALUE, String.valueOf(id));
                            r.setProperty(FormUtil.PROPERTY_LABEL, label);
                            results.add(r);
                        }
                    } else {
                        System.err.println("HTTP Request failed with status code: " + statusCode);
                    }

                    // Ensure the response is closed properly
                    response.close();
                } catch (IOException | ParseException ex) {
                    LogUtil.error(getClassName(), ex, ex.getMessage());
                } finally {
                    try {
                        httpClient.close();
                    } catch (IOException ex) {
                        LogUtil.error(getClassName(), ex, ex.getMessage());
                    }
                }
            } else if (OPT_TAGS.equalsIgnoreCase(options)) {
                String url = serverUrl + "/api/v4/tags/?_ordering=label";
                CloseableHttpClient httpClient = HttpClients.createDefault();

                try {
                    HttpGet httpGet = new HttpGet(url);
                    String auth = username + ":" + password;
                    byte[] encodedAuth = java.util.Base64.getEncoder().encode(auth.getBytes());
                    String authHeader = "Basic " + new String(encodedAuth);
                    httpGet.setHeader(HttpHeaders.AUTHORIZATION, authHeader);
                    CloseableHttpResponse response = httpClient.execute(httpGet);
                    int statusCode = response.getStatusLine().getStatusCode();
                    if (statusCode == 200) { // HTTP 200 OK
                        // Parse and print the response content
                        String responseBody = EntityUtils.toString(response.getEntity());
                        JSONObject jSONObject = new JSONObject(responseBody);
                        JSONArray array = (JSONArray) jSONObject.get("results");

                        if ("true".equals(getPropertyString("addEmptyOption"))) {
                            FormRow emptyRow = new FormRow();
                            emptyRow.setProperty(FormUtil.PROPERTY_VALUE, "");
                            emptyRow.setProperty(FormUtil.PROPERTY_LABEL, getPropertyString("emptyLabel"));
                            results.add(emptyRow);
                        }

                        for (int i = 0; i < array.length(); i++) {
                            FormRow r = new FormRow();
                            JSONObject cabinet = (JSONObject) array.get(i);
                            int id = (int) cabinet.get("id");
                            String label = (String) cabinet.get("label");

                            r.setProperty(FormUtil.PROPERTY_VALUE, String.valueOf(id));
                            r.setProperty(FormUtil.PROPERTY_LABEL, label);
                            results.add(r);
                        }
                    } else {
                        LogUtil.info(getClassName(), "HTTP Request failed with status code: " + statusCode);
                    }
                    response.close();
                } catch (IOException | ParseException ex) {
                    LogUtil.error(getClassName(), ex, ex.getMessage());
                } finally {
                    try {
                        httpClient.close();
                    } catch (IOException ex) {
                        LogUtil.error(getClassName(), ex, ex.getMessage());
                    }
                }
            }
        }

        return results;
    }

    @Override
    public String getName() {
        return "Mayan Option Binder";
    }

    @Override
    public String getVersion() {
        return "8.0.0";
    }

    @Override
    public String getDescription() {
        return "To load cabinets, sub cabinets, document types and tags from Mayan EDMS.";
    }

    @Override
    public String getLabel() {
        return "Mayan Option Binder";
    }

    @Override
    public String getClassName() {
        return this.getClass().getName();
    }

    @Override
    public String getPropertyOptions() {
        return AppUtil.readPluginResource(getClassName(), "/properties/mayanOptionBinder.json", null, true, "messages/MayanOptionBinder");
    }
}
