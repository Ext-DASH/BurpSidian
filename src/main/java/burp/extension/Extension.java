package burp.extension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.scope.Scope;

import burp.extension.models.PlainTextRequestResponse;
import burp.extension.models.Setting;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class Extension implements BurpExtension {
    // GLOBALS
    public MontoyaApi api;
    private final String extensionName = "BurpSidian";
    private final String version = "b1.0.0";

    private boolean monitoring = false;
    private Thread monitorThread;

    private final String[] resourceExtensions = {".jpg", ".jpeg", ".png", ".gif", ".svg", ".css", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".js"};
    // PlainTextReqRes holder
    private final Map<String, PlainTextRequestResponse> entries = new HashMap<>();
    // settings
    private final Map<String, Setting> settings = new HashMap<>();
    
    //add settings to hashmap
    {
        settings.put("showHTMLComments", new Setting("showHTMLComments", "checkbox", "true", "Include HTML comments found in response in markdown", null, null, false, null, null, false));
        settings.put("showInlineJS", new Setting("showInlineJS", "checkbox", "true", "Include Inline JavaScript found in responses in markdown", null, null, false, null, null, false));
        settings.put("skipResources", new Setting("skipResources", "checkbox", "true", "Don't create markdown pages for images/css", null, null, false, null, null, false));
        settings.put("monitoringButton", new Setting("monitoringButton", "button", null, null, "Start Montoring", "monitor", false, null, null, false));
        settings.put("outputDirButton", new Setting("outputDirButton", "button", "/home/kali/Documents/Projects/Pentests/GinJuice BurpSidian Test/2. Map", "Obsidian Vault/Output Location", "Browse", "browse", true, "directory", "outputDirTxt", false));
    }

    // initialize burp panel
    private Component initJPanel(MontoyaApi montoyaApi) {
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
                                startMonitoringThread();
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

                                int returnVal = chooser.showOpenDialog(null);
                                String selectedDir = chooser.getSelectedFile().getAbsolutePath();

                                txtField.setText(selectedDir);
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
                
    }

    //methods
    public void startMonitoringThread() {
        monitorThread = new Thread(() -> {
            
            //get list sitemap, use api.isInScope(url)

            while (monitoring) {
                try {                  
                    Scope scope = api.scope();
                    SiteMap siteMap = api.siteMap();
                    System.out.println("monitoring...");
                    for (HttpRequestResponse reqRes : siteMap.requestResponses()) {
                        String url = reqRes.request().url();
                        //if url is in scope and we have visited the path and the response was anything other than 404
                        if(scope.isInScope(url) && reqRes.hasResponse() && reqRes.response().statusCode() != 404) {
                            HttpRequest request = reqRes.request();
                            HttpResponse response = reqRes.response();
                        }
                    }
                    Thread.sleep(500);

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
        monitorThread.start();
    }

}

