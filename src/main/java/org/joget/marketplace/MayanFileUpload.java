package org.joget.marketplace;

import com.google.common.net.HttpHeaders;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.model.Element;
import org.joget.apps.form.model.FileDownloadSecurity;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.ParseException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import org.joget.apps.form.model.Form;
import org.joget.apps.form.model.FormBuilderPaletteElement;
import org.joget.apps.form.model.FormData;
import org.joget.apps.form.model.FormPermission;
import org.joget.apps.form.model.FormRow;
import org.joget.apps.form.model.FormRowSet;
import org.joget.apps.form.service.FormUtil;
import org.joget.apps.userview.model.Permission;
import org.joget.apps.userview.model.PwaOfflineResources;
import org.joget.commons.util.FileManager;
import org.joget.commons.util.FileStore;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.ResourceBundleUtil;
import org.joget.commons.util.SecurityUtil;
import org.joget.commons.util.StringUtil;
import org.joget.directory.model.User;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.base.PluginWebSupport;
import org.joget.workflow.model.service.WorkflowUserManager;
import org.joget.workflow.util.WorkflowUtil;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.web.multipart.MultipartFile;

public class MayanFileUpload extends Element implements FormBuilderPaletteElement, FileDownloadSecurity, PluginWebSupport, PwaOfflineResources {

    private final static String MESSAGE_PATH = "messages/MayanFileUpload";

    @Override
    public String getName() {
        return "Mayan File Upload";
    }

    @Override
    public String getVersion() {
        return Activator.VERSION;
    }

    @Override
    public String getDescription() {
        return "Mayan FileUpload Element";
    }

    @Override
    public String renderTemplate(FormData formData, Map dataModel) {
        String template = "mayanDmsFileUpload.ftl";

        String serverUrl = getPropertyString("serverUrl");
        String username = getPropertyString("username");
        String password = getPropertyString("password");
        password = SecurityUtil.decrypt(password);

        JSONObject jsonParams = new JSONObject();

        // set value
        String[] values = FormUtil.getElementPropertyValues(this, formData);

        Map<String, String> tempFilePaths = new LinkedHashMap<>();
        Map<String, String> filePaths = new LinkedHashMap<>();

        String filePathPostfix = "_path";
        String id = FormUtil.getElementParameterName(this);

        //check is there a stored value
        String storedValue = formData.getStoreBinderDataProperty(this);
        if (storedValue != null) {
            values = storedValue.split(";");
        } else {
            //if there is no stored value, get the temp files
            String[] tempExisting = formData.getRequestParameterValues(id + filePathPostfix);

            if (tempExisting != null && tempExisting.length > 0) {
                values = tempExisting;
            }
        }

        Form form = FormUtil.findRootForm(this);
        if (form != null) {
            form.getPropertyString(FormUtil.PROPERTY_ID);
        }
        String appId = "";
        String appVersion = "";

        AppDefinition appDef = AppUtil.getCurrentAppDefinition();

        if (appDef != null) {
            appId = appDef.getId();
            appVersion = appDef.getVersion().toString();
        }

        for (String value : values) {
            // check if the file is in temp file

            Map<String, String> fileMap = parseFileName(value);
            value = fileMap.get("filename");
            String documentId = fileMap.get("documentId");

            File file = FileManager.getFileByPath(value);

            if (file != null) {
                tempFilePaths.put(value, file.getName());
            } else if (value != null && !value.isEmpty()) {
                // determine actual path for the file uploads
                String fileName = value;
                String encodedFileName = fileName;
                if (fileName != null) {
                    try {
                        encodedFileName = URLEncoder.encode(fileName, "UTF8").replaceAll("\\+", "%20");
                    } catch (UnsupportedEncodingException ex) {
                        // ignore
                    }
                }

                jsonParams.put("serverUrl", serverUrl);
                jsonParams.put("username", username);
                jsonParams.put("password", password);
                String params = StringUtil.escapeString(SecurityUtil.encrypt(jsonParams.toString()), StringUtil.TYPE_URL, null);

                String filePath = "/web/json/app/" + appId + "/" + appVersion + "/plugin/org.joget.marketplace.MayanFileUpload/service?dIf=" + documentId + "&action=download&params=" + params;
                filePaths.put(filePath, value);
            }
        }

        if (!tempFilePaths.isEmpty()) {
            dataModel.put("tempFilePaths", tempFilePaths);
        }
        if (!filePaths.isEmpty()) {
            dataModel.put("filePaths", filePaths);
        }

        String html = FormUtil.generateElementHtml(this, formData, template, dataModel);
        return html;
    }

    public static Map<String, String> parseFileName(String input) {
        Map<String, String> resultMap = new HashMap<>();

        // Split the input based on "|"
        String[] parts = input.split("\\|");

        if (parts.length == 2) {
            // Extract the filename (part before "|")
            String filename = parts[0].trim();
            String documentId = parts[1].trim();

            resultMap.put("filename", filename);
            resultMap.put("documentId", documentId);
        } else {
            System.err.println("Invalid input format.");
        }

        return resultMap;
    }

    @Override
    public FormData formatDataForValidation(FormData formData) {
        String filePathPostfix = "_path";
        String id = FormUtil.getElementParameterName(this);
        if (id != null) {
            String[] tempFilenames = formData.getRequestParameterValues(id);
            String[] tempExisting = formData.getRequestParameterValues(id + filePathPostfix);

            List<String> filenames = new ArrayList<>();
            if (tempFilenames != null && tempFilenames.length > 0) {
                filenames.addAll(Arrays.asList(tempFilenames));
            }

            if (tempExisting != null && tempExisting.length > 0) {
                filenames.addAll(Arrays.asList(tempExisting));
            }

            if (filenames.isEmpty()) {
                formData.addRequestParameterValues(id, new String[]{""});
            } else if (!"true".equals(getPropertyString("multiple"))) {
                formData.addRequestParameterValues(id, new String[]{filenames.get(0)});
            } else {
                formData.addRequestParameterValues(id, filenames.toArray(new String[]{}));
            }
        }
        return formData;
    }

    @Override
    public FormRowSet formatData(FormData formData) {
        FormRowSet rowSet = null;

        String id = getPropertyString(FormUtil.PROPERTY_ID);

        String serverUrl = getPropertyString("serverUrl");
        String username = getPropertyString("username");
        String password = getPropertyString("password");
        password = SecurityUtil.decrypt(password);

        String documentType = getPropertyString("documentType");
        String cabinet = getPropertyString("cabinet");
        String tag = getPropertyString("tag");

        String dtValue = formData.getRequestParameter(documentType);
        String cabinetValue = formData.getRequestParameter(cabinet);
        String tagValue = formData.getRequestParameter(tag);

        if (serverUrl.endsWith("/")) {
            serverUrl = serverUrl.substring(0, serverUrl.length() - 1);
        }

        Set<String> remove = null;
        if ("true".equals(getPropertyString("removeFile"))) {
            remove = new HashSet<String>();
            Form form = FormUtil.findRootForm(this);
            String originalValues = formData.getLoadBinderDataProperty(form, id);
            if (originalValues != null) {
                remove.addAll(Arrays.asList(originalValues.split(";")));
            }
        }

        // get value
        if (id != null) {
            String[] values = FormUtil.getElementPropertyValues(this, formData);
            if (values != null && values.length > 0) {
                // set value into Properties and FormRowSet object
                FormRow result = new FormRow();
                List<String> resultedValue = new ArrayList<String>();
                List<String> filePaths = new ArrayList<String>();

                for (String value : values) {
                    // check if the file is in temp file
                    File file = FileManager.getFileByPath(value);
                    if (file != null) {

                        // upload file to mayan edms
                        int documentId = uploadFileMayanDms(serverUrl + "/api/v4/documents/upload/", username, password, file, dtValue);

                        // assign cabinet
                        if (cabinetValue != null && !cabinetValue.isEmpty()) {
                            assignedCabinet(serverUrl + "/api/v4/cabinets/" + cabinetValue + "/documents/add/", username, password, documentId);
                        }
                        // assign tag
                        if (tagValue != null && !tagValue.isEmpty()) {
                            assignedTag(serverUrl + "/api/v4/documents/" + documentId + "/tags/attach/", username, password, tagValue);
                        }

                        filePaths.add(value + "|" + documentId);
                        resultedValue.add(file.getName() + "|" + documentId);
                    } else {
                        if (remove != null && !value.isEmpty()) {
                            remove.removeIf(item -> {
                                    if (item.contains(value)) {
                                        resultedValue.add(item);
                                        return true;
                                    }
                                return false;
                            });
                        }   
                    }
                }

                if (!filePaths.isEmpty()) {
                    result.putTempFilePath(id, filePaths.toArray(new String[]{}));
                }

                if (remove != null && !remove.isEmpty() && !remove.contains("")) {
                    result.putDeleteFilePath(id, remove.toArray(new String[]{}));
                    for (String r : remove) {
                        Map<String, String> fileMap = parseFileName(r);
                        String documentId = fileMap.get("documentId");
                    
                        if (documentId != null && !documentId.isEmpty()) {
                            // delete file(s) from mayan
                            deleteFileMayanDms(serverUrl + "/api/v4/documents/" + documentId + "/", username, password);                      
                        }
                    }
                }

                // formulate values
                String delimitedValue = FormUtil.generateElementPropertyValues(resultedValue.toArray(new String[]{}));
                String paramName = FormUtil.getElementParameterName(this);
                formData.addRequestParameterValues(paramName, resultedValue.toArray(new String[]{}));

                if (delimitedValue == null) {
                    delimitedValue = "";
                }

                // set value into Properties and FormRowSet object
                result.setProperty(id, delimitedValue);
                rowSet = new FormRowSet();
                rowSet.add(result);

                String filePathPostfix = "_path";
                formData.addRequestParameterValues(id + filePathPostfix, new String[]{});
            }
        }

        return rowSet;
    }

    private String getDocument(String url, String username, String password) {
        String downloadUrl = "";
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
                String responseBody = EntityUtils.toString(response.getEntity());
                JSONObject jSONObject = new JSONObject(responseBody);
                JSONObject fileLatest = (JSONObject) jSONObject.get("file_latest");
                downloadUrl = (String) fileLatest.get("download_url");

            } else {
                LogUtil.info(getClassName(), "HTTP Request failed with status code: " + statusCode);
            }
            response.close();
        } catch (IOException ex) {
            LogUtil.error(getClassName(), ex, ex.getMessage());
        } finally {
            try {
                httpClient.close();
            } catch (IOException ex) {
                LogUtil.error(getClassName(), ex, ex.getMessage());
            }
        }
        return downloadUrl;
    }

    private int uploadFileMayanDms(String url, String username, String password, File file, String documentTypeId) {
        int documentId = 0;

        CloseableHttpClient httpClient = HttpClients.createDefault();
        try {
            HttpPost httpPost = new HttpPost(url);

            String auth = username + ":" + password;
            byte[] encodedAuth = java.util.Base64.getEncoder().encode(auth.getBytes());
            String authHeader = "Basic " + new String(encodedAuth);
            httpPost.setHeader(HttpHeaders.AUTHORIZATION, authHeader);

            MultipartEntityBuilder entityBuilder = MultipartEntityBuilder.create();

            entityBuilder.addBinaryBody("file", file);
            entityBuilder.addTextBody("document_type_id", documentTypeId);
            entityBuilder.addTextBody("label", file.getName());
            httpPost.setEntity(entityBuilder.build());

            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == 201) {
                String responseBody = EntityUtils.toString(response.getEntity());
                JSONObject jSONObject = new JSONObject(responseBody);
                documentId = (int) jSONObject.get("pk");
            } else {
                LogUtil.info(getClassName(), "HTTP Request failed with status code: " + statusCode);
            }
        } catch (IOException | ParseException | JSONException ex) {
            LogUtil.error(getClassName(), ex, ex.getMessage());
        } finally {
            try {
                httpClient.close();
            } catch (IOException ex) {
                LogUtil.error(getClassName(), ex, ex.getMessage());
            }
        }
        return documentId;
    }

    private void deleteFileMayanDms(String url, String username, String password) {
        String responseBody = "";
        CloseableHttpClient httpClient = HttpClients.createDefault();
        try {
            HttpDelete httpDelete = new HttpDelete(url);

            String auth = username + ":" + password;
            byte[] encodedAuth = java.util.Base64.getEncoder().encode(auth.getBytes());
            String authHeader = "Basic " + new String(encodedAuth);
            httpDelete.setHeader(HttpHeaders.AUTHORIZATION, authHeader);

            HttpResponse response = httpClient.execute(httpDelete);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode != 204) {
                LogUtil.info(getClassName(), "HTTP Request failed with status code: " + statusCode);
            }
        } catch (IOException | ParseException | JSONException ex) {
            LogUtil.error(getClassName(), ex, ex.getMessage());
        } finally {
            try {
                httpClient.close();
            } catch (IOException ex) {
                LogUtil.error(getClassName(), ex, ex.getMessage());
            }
        }
    }

    private void assignedCabinet(String url, String username, String password, int documentId) {
        String payload = "{\"document\": " + documentId + "}";
        CloseableHttpClient httpClient = HttpClients.createDefault();
        try {
            HttpPost httpPost = new HttpPost(url);
            String auth = username + ":" + password;
            byte[] encodedAuth = java.util.Base64.getEncoder().encode(auth.getBytes());
            String authHeader = "Basic " + new String(encodedAuth);
            httpPost.setHeader(HttpHeaders.AUTHORIZATION, authHeader);
            StringEntity requestEntity = new StringEntity(payload);
            requestEntity.setContentType("application/json");
            httpPost.setEntity(requestEntity);
            HttpResponse response = httpClient.execute(httpPost);
            int sCode = response.getStatusLine().getStatusCode();
            if (sCode == 200) { // HTTP 200 OK
                HttpEntity entity = response.getEntity();
                String responseBody = EntityUtils.toString(entity);
            } else {
                LogUtil.info(getClassName(), "HTTP Request failed with status code: " + sCode);
            }
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

    private void assignedTag(String url, String username, String password, String tagId) {
        String payload = "{\"tag\": " + tagId + "}";
        CloseableHttpClient httpClient = HttpClients.createDefault();
        try {
            HttpPost httpPost = new HttpPost(url);
            String auth = username + ":" + password;
            byte[] encodedAuth = java.util.Base64.getEncoder().encode(auth.getBytes());
            String authHeader = "Basic " + new String(encodedAuth);
            httpPost.setHeader(HttpHeaders.AUTHORIZATION, authHeader);
            StringEntity requestEntity = new StringEntity(payload);
            requestEntity.setContentType("application/json");
            httpPost.setEntity(requestEntity);
            HttpResponse response = httpClient.execute(httpPost);
            int sCode = response.getStatusLine().getStatusCode();
            if (sCode == 201 || sCode == 200) { // HTTP 200 OK
                HttpEntity entity = response.getEntity();
                String responseBody = EntityUtils.toString(entity);
            } else {
                LogUtil.info(getClassName(), "HTTP Request failed with status code: " + sCode);
            }
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

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public String getFormBuilderTemplate() {
        return "<label class='label'>" + ResourceBundleUtil.getMessage("org.joget.apps.form.lib.FileUpload.pluginLabel") + "</label><input type='file' />";
    }

    @Override
    public String getLabel() {
        return "Mayan File Upload";
    }

    @Override
    public String getPropertyOptions() {
        return AppUtil.readPluginResource(getClassName(), "/properties/mayanFileUpload.json", null, true, MESSAGE_PATH);
    }

    @Override
    public String getFormBuilderCategory() {
        return "Marketplace";
    }

    @Override
    public int getFormBuilderPosition() {
        return 900;
    }

    @Override
    public String getFormBuilderIcon() {
        return "<i class=\"fas fa-upload\"></i>";
    }

    @Override
    public Boolean selfValidate(FormData formData) {
        String id = FormUtil.getElementParameterName(this);
        Boolean valid = true;
        String error = "";
        try {
            String[] values = FormUtil.getElementPropertyValues(this, formData);

            for (String value : values) {
                File file = FileManager.getFileByPath(value);
                if (file != null) {
                    if (getPropertyString("maxSize") != null && !getPropertyString("maxSize").isEmpty()) {
                        long maxSize = Long.parseLong(getPropertyString("maxSize")) * 1024;

                        if (file.length() > maxSize) {
                            valid = false;
                            error += getPropertyString("maxSizeMsg") + " ";

                        }
                    }
                    if (getPropertyString("fileType") != null && !getPropertyString("fileType").isEmpty()) {
                        String[] fileType = getPropertyString("fileType").split(";");
                        String filename = file.getName().toUpperCase();
                        Boolean found = false;
                        for (String type : fileType) {
                            if (filename.endsWith(type.toUpperCase())) {
                                found = true;
                            }
                        }
                        if (!found) {
                            valid = false;
                            error += getPropertyString("fileTypeMsg");
                            FileManager.deleteFile(file);
                        }
                    }
                }
            }

            if (!valid) {
                formData.addFormError(id, error);
            }
        } catch (Exception e) {
        }

        return valid;
    }

    public boolean isDownloadAllowed(Map requestParameters) {
        String permissionType = getPropertyString("permissionType");
        if (permissionType.equals("public")) {
            return true;
        } else if (permissionType.equals("custom")) {
            Object permissionElement = getProperty("permissionPlugin");
            if (permissionElement != null && permissionElement instanceof Map) {
                Map elementMap = (Map) permissionElement;
                String className = (String) elementMap.get("className");
                Map<String, Object> properties = (Map<String, Object>) elementMap.get("properties");

                //convert it to plugin
                PluginManager pm = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");
                Permission plugin = (Permission) pm.getPlugin(className);
                if (plugin != null && plugin instanceof FormPermission) {
                    WorkflowUserManager workflowUserManager = (WorkflowUserManager) AppUtil.getApplicationContext().getBean("workflowUserManager");
                    User user = workflowUserManager.getCurrentUser();

                    plugin.setProperties(properties);
                    plugin.setCurrentUser(user);
                    plugin.setRequestParameters(requestParameters);

                    return plugin.isAuthorize();
                }
            }
            return false;
        } else {
            return !WorkflowUtil.isCurrentUserAnonymous();
        }
    }

    public String getServiceUrl() {
        String url = WorkflowUtil.getHttpServletRequest().getContextPath() + "/web/json/plugin/org.joget.marketplace.MayanFileUpload/service";
        AppDefinition appDef = AppUtil.getCurrentAppDefinition();

        //create nonce
        String paramName = FormUtil.getElementParameterName(this);
        String fileType = getPropertyString("fileType");
        String nonce = SecurityUtil.generateNonce(new String[]{"FileUpload", appDef.getAppId(), appDef.getVersion().toString(), paramName, fileType}, 1);

        try {
            url = url + "?_nonce=" + URLEncoder.encode(nonce, "UTF-8") + "&_paramName=" + URLEncoder.encode(paramName, "UTF-8") + "&_appId=" + URLEncoder.encode(appDef.getAppId(), "UTF-8") + "&_appVersion=" + URLEncoder.encode(appDef.getVersion().toString(), "UTF-8") + "&_ft=" + URLEncoder.encode(fileType, "UTF-8");
        } catch (Exception e) {
        }
        return url;
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String nonce = request.getParameter("_nonce");
        String paramName = request.getParameter("_paramName");
        String appId = request.getParameter("_appId");
        String appVersion = request.getParameter("_appVersion");
        String filePath = request.getParameter("_path");
        String fileType = request.getParameter("_ft");

        String action = request.getParameter("action");
        String documentId = request.getParameter("dIf");

        if ("download".equals(action) && (documentId != null && !documentId.isEmpty())) {
            String params = SecurityUtil.decrypt(request.getParameter("params"));
            JSONObject jsonParams = new JSONObject(params);
            String serverUrl = jsonParams.getString("serverUrl");
            String username = jsonParams.getString("username");
            String password = jsonParams.getString("password");
            // call the get document api and get the file id
            String downloadUrl = getDocument(serverUrl + "/api/v4/documents/" + documentId + "/", username, password);
            response.sendRedirect(downloadUrl);
        }

        if (SecurityUtil.verifyNonce(nonce, new String[]{"FileUpload", appId, appVersion, paramName, fileType})) {
            if ("POST".equalsIgnoreCase(request.getMethod())) {

                try {
                    JSONObject obj = new JSONObject();
                    try {
                        // handle multipart files
                        String validatedParamName = SecurityUtil.validateStringInput(paramName);
                        MultipartFile file = (MultipartFile) FileStore.getFile(validatedParamName);
                        if (file != null && file.getOriginalFilename() != null && !file.getOriginalFilename().isEmpty()) {
                            String ext = file.getOriginalFilename().substring(file.getOriginalFilename().lastIndexOf(".")).toLowerCase();
                            if (fileType != null && (fileType.isEmpty() || fileType.contains(ext + ";") || fileType.endsWith(ext))) {
                                String path = FileManager.storeFile(file);
                                obj.put("path", path);
                                obj.put("filename", file.getOriginalFilename());
                                obj.put("newFilename", path.substring(path.lastIndexOf(File.separator) + 1));
                            } else {
                                obj.put("error", ResourceBundleUtil.getMessage("form.fileupload.fileType.msg.invalidFileType"));
                            }
                        }

                        Collection<String> errorList = FileStore.getFileErrorList();
                        if (errorList != null && !errorList.isEmpty() && errorList.contains(paramName)) {
                            obj.put("error", ResourceBundleUtil.getMessage("general.error.fileSizeTooLarge", new Object[]{FileStore.getFileSizeLimit()}));
                        }
                    } catch (Exception e) {
                        obj.put("error", e.getLocalizedMessage());
                    } finally {
                        FileStore.clear();
                    }
                    obj.write(response.getWriter());
                } catch (Exception ex) {
                    LogUtil.error(getClassName(), ex, ex.getMessage());
                }
            } else if (filePath != null && !filePath.isEmpty()) {
                String normalizedFilePath = SecurityUtil.normalizedFileName(filePath);

                File file = FileManager.getFileByPath(normalizedFilePath);
                if (file != null) {
                    ServletOutputStream stream = response.getOutputStream();
                    DataInputStream in = new DataInputStream(new FileInputStream(file));
                    byte[] bbuf = new byte[65536];

                    try {
                        String contentType = request.getSession().getServletContext().getMimeType(file.getName());
                        if (contentType != null) {
                            response.setContentType(contentType);
                        }

                        // send output
                        int length = 0;
                        while ((in != null) && ((length = in.read(bbuf)) != -1)) {
                            stream.write(bbuf, 0, length);
                        }
                    } catch (Exception e) {

                    } finally {
                        in.close();
                        stream.flush();
                        stream.close();
                    }
                } else {
                    response.sendError(HttpServletResponse.SC_NOT_FOUND);
                    return;
                }
            }
        } else {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, ResourceBundleUtil.getMessage("general.error.error403"));
        }
    }

    @Override
    public Set<String> getOfflineStaticResources() {
        Set<String> urls = new HashSet<>();
        String contextPath = AppUtil.getRequestContextPath();
        urls.add(contextPath + "/js/dropzone/dropzone.css");
        urls.add(contextPath + "/js/dropzone/dropzone.js");
        urls.add(contextPath + "/plugin/org.joget.apps.form.lib.FileUpload/js/jquery.fileupload.js");

        return urls;
    }
}
