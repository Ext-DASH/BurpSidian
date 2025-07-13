package burp.extension.models;

import java.awt.event.ActionListener;
import java.security.cert.Extension;
import java.awt.event.ActionEvent;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JButton;

import burp.api.montoya.MontoyaApi;
public class Setting {
    //global
    public boolean montioring = false;

    //required
    private String name;
    private String type;
    private String label;
    private String defaultValue;

    //not required
    private String displayText;
    private String txtFieldDefaultValue;
    private String fileMode;
    private String listenerName;
    private String txtFieldName;
    private boolean hasTextField;
    private boolean txtFieldEnabled;

    private MontoyaApi api;

    private ActionListener listener;
    //constructor
    public Setting(String name, String type, String defaultValue, String label, String displayText, String listenerName, 
    boolean hasTextField, String fileMode, String txtFieldName, boolean txtFieldEnabled) {
        this.name = name;
        this.type = type;
        this.defaultValue = defaultValue;
        this.label = label;
        this.displayText = displayText;
        this.hasTextField = hasTextField;
        this.fileMode = fileMode;
        this.txtFieldName = txtFieldName;
        this.txtFieldEnabled = txtFieldEnabled;
        this.listenerName = listenerName;
    }

    //getters
    public String getName() { return name; }
    public String getType() { return type; }
    public String getDefaultValue() { return defaultValue; }
    public String getLabel() { return label; }
    public boolean getHasTextField() { return hasTextField; }
    public String getFileMode() { return fileMode; }
    public String getTextFieldName() { return txtFieldName; }
    public boolean textFieldEnabled() { return txtFieldEnabled; }
    public String getDisplayText() { return displayText; }
    public String getListenerName() { return listenerName; }

    public boolean getMonitoring() { return montioring; }
    public ActionListener getListener() { return listener; }

    //setters
    public void setDefaultValue(String value) {
        this.defaultValue = value;
    }
    public void setDisplayText(String value) {
        this.displayText = value;
    }

    
    //methods
    
}