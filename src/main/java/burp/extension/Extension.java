package burp.extension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.scope.Scope;
import burp.extension.models.MarkdownWriter;
import burp.extension.models.PlainTextRequestResponse;
import burp.extension.models.Setting;

import java.io.FileWriter;
import java.io.IOException;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.Map;


public class Extension implements BurpExtension {
    // GLOBALS
    public MontoyaApi api;
    private final String extensionName = "BurpSidian";
    private final String version = "v1.0.3";
    
    private final String[] resourceExtensions = {".mp4", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".css", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".json"};

    private final Map<String, PlainTextRequestResponse> loggedPages = new HashMap<>();
    Set<String> loggedResourceUrls = new HashSet<>();
    HashMap<String, String> loggedPageUrls = new HashMap<>();
    private boolean monitoring = false;
    private Thread monitorThread;
    // settings
    private final Map<String, Setting> settings = new HashMap<>();
    
    //add settings to hashmap
    {
        // settings.put("showHTMLComments", new Setting("showHTMLComments", "checkbox", "true", "Include HTML comments found in response in markdown", null, null, false, null, null, false));
        // settings.put("showInlineJS", new Setting("showInlineJS", "checkbox", "true", "Include Inline JavaScript found in responses in markdown", null, null, false, null, null, false));
        // settings.put("skipResources", new Setting("skipResources", "checkbox", "true", "Don't create markdown pages for images/css", null, null, false, null, null, false));
        settings.put("monitoringButton", new Setting("monitoringButton", "button", null, null, "Start Montoring", "monitor", false, null, null, false));
        settings.put("outputDirButton", new Setting("outputDirButton", "button", "/home/assess/Desktop/Pen tests/Pen Tests/extension test/2. Map", "Obsidian Vault/Output Location", "Browse", "browse", true, "directory", "outputDirTxt", false));
    }

    // initialize burp panel
    private Component initJPanel(MontoyaApi api) {
        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new GridBagLayout());
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.anchor = GridBagConstraints.WEST;
        
        int row = 0;
        
        for (Map.Entry<String, Setting> setting : settings.entrySet()) {
            gbc.gridy = row;
            Setting settingValue = setting.getValue();
            
            switch (settingValue.getType()) {
                case "checkbox":
                    JCheckBox checkbox = new JCheckBox(
                        settingValue.getLabel(), 
                        Boolean.parseBoolean(settingValue.getDefaultValue())
                    );
                    gbc.gridx = 0;
                    gbc.gridwidth = 2;
                    settingsPanel.add(checkbox, gbc);
                    break;
                case "button":
                    
                    JLabel label = new JLabel(
                        settingValue.getLabel()
                    );
                    gbc.gridx = 0;
                    gbc.gridwidth = 1;
                    settingsPanel.add(label);
                    JButton btn = new JButton(
                        settingValue.getDisplayText()
                    );
                    if ("monitor".equals(settingValue.getListenerName())) {
                        btn.addActionListener(e -> {
                            if (!monitoring) {
                                monitoring = true;
                                startMonitoringThread(api);
                                btn.setText("Stop Monitoring");
                            } else {
                                monitoring = false;
                                btn.setText("Start Monitoring");
                            }
                        });
                    }
                    btn.addActionListener(settingValue.getListener());
                    gbc.gridx = 1;
                    settingsPanel.add(btn, gbc);

                    if (settingValue.getHasTextField()) {
                        gbc.gridx = 2;
                        JTextField txtField = new JTextField(30);
                        txtField.setText(settingValue.getDefaultValue());
                        txtField.setEnabled(settingValue.textFieldEnabled());
                        if ("browse".equals(settingValue.getListenerName())) {
                            btn.addActionListener(e -> {
                                JFileChooser chooser = new JFileChooser();
                                chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

                                chooser.showOpenDialog(null);
                                String selectedDir = chooser.getSelectedFile().getAbsolutePath();

                                txtField.setText(selectedDir);
                                settingValue.setDefaultValue(selectedDir);
                            });
                        }
                        settingsPanel.add(txtField, gbc);
                    }
                    break;
            }
            row++;
            System.err.print(row);
        }
        return settingsPanel;
    }
    // end globals
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(extensionName);
        api.userInterface().registerSuiteTab(extensionName, initJPanel(api));
        System.out.println("BurpSidian Version: " + version);
                
    }

    //methods
    public void startMonitoringThread(MontoyaApi api) {
        String dirPath = settings.get("outputDirButton").getDefaultValue().concat("/");
      
        monitorThread = new Thread(() -> {
            while (monitoring) {
                try {  
                    //monitor logic              
                    Scope scope = api.scope();
                    SiteMap siteMap = api.siteMap();
                    System.out.println("monitoring...");
                    for (HttpRequestResponse reqRes : siteMap.requestResponses()) {
                        String url = reqRes.request().url();
                        //strip url of params
                        String strippedUrl = url.contains("?") ? url.split("\\?")[0] : url;

                        boolean isResource = Arrays.stream(resourceExtensions).anyMatch(url::endsWith);
                        boolean isStaticInclude = url.endsWith(".js");
                        boolean isResourceLogged = loggedResourceUrls.contains(strippedUrl);
                        boolean isPageLogged = loggedPageUrls.containsKey(strippedUrl);
                        //ALSO NEED TO CHECK METHOD FOR POST ETC
                        
                        //url is in scope, has a response that is not 404, is not a resource and has not been logged
                        boolean needsLogging = scope.isInScope(url) && 
                        reqRes.hasResponse() && 
                        reqRes.response().statusCode() != 404 && 
                        reqRes.response().statusCode() != 302 && 
                        !isResource && !isStaticInclude &&
                        !isPageLogged;

                        boolean needsUpdateCheck = scope.isInScope(url) && 
                        reqRes.hasResponse() && 
                        reqRes.response().statusCode() != 404 && 
                        !isResource && 
                        isPageLogged;

                        if (scope.isInScope(url) && isResource && !isResourceLogged) {
                            //log all resource files
                            MarkdownWriter.appendToResourcesLog(dirPath + "Resources.md", url);
                            MarkdownWriter.appendToSiteLog(url, reqRes, true, dirPath + "SiteLog.md");
                            loggedResourceUrls.add(url);
                        } else if (scope.isInScope(url) && isStaticInclude && !isResourceLogged) {
                            MarkdownWriter.appendToResourcesLog(dirPath + "Static Inclusions.md", url);
                            MarkdownWriter.appendToSiteLog(url, reqRes, true, dirPath + "SiteLog.md");
                            loggedResourceUrls.add(url);
                        } else if(needsLogging) {
                            HttpRequest request = reqRes.request();
                            HttpResponse response = reqRes.response();

                            System.out.println("Create page for: " + strippedUrl);
                            //process the request/response
                            PlainTextRequestResponse plainTextRequestResponse = PlainTextRequestResponse.from(request, response);
                            
                            MarkdownWriter.createPageMd(dirPath, plainTextRequestResponse, response);
                            MarkdownWriter.appendToSiteLog(url, reqRes, false, dirPath + "SiteLog.md");

                            loggedPages.put(strippedUrl, plainTextRequestResponse);

                            //put url + method in logged urls
                            loggedPageUrls.put(strippedUrl, request.method());
                            System.out.println(loggedPageUrls.toString());
                            
                        } else if (needsUpdateCheck) {
                            loggedPages.get(strippedUrl);
                        }
                    }
                    Thread.sleep(5000);

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
        monitorThread.start();
    }

    
}

