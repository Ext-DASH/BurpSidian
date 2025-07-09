from burp import IBurpExtender, ITab

from javax.swing import JPanel, JLabel, JTextField, JCheckBox, JButton, JFileChooser, JScrollPane, JTextArea, JComboBox, JSpinner, SpinnerNumberModel, JOptionPane
from javax.swing.border import TitledBorder
from java.awt import GridBagLayout, GridBagConstraints, Insets, FlowLayout, BorderLayout
from java.awt.event import ActionListener
from java.io import File

import json
import os
import threading
import time

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        self.monitoring = False  # Flag to control monitoring loop
        self.monitorThread = None  # Thread placeholder

        callbacks.setExtensionName("BurpSidian")
        
        # base settings
        self.settingsElements = {
            'outputDirButton': {
                'type': 'button',
                'displayText': 'Browse',
                'txtFieldDefaultValue': os.path.expanduser('~'),
                'label': 'Obsidian Vault',
                'fileMode': 'directory',
                'listener': self._browse,
                'action': BrowseDirectoryListener(ActionListener),
                'hasTextField': True,
                'txtFieldEnabled': False
            },
            'target': {
                'type': 'txtField',
                'label': 'Target:',
            },
            'includeRequests': {
                'type': 'checkbox',
                'defaultValue': True,
                'label': 'Include sample request in markdown !!UNIMPLEMENTED'
            },
            'includeResponses': {
                'type': 'checkbox',
                'defaultValue': True,
                'label': 'Include sample response in markdown !!UNIMPLEMENTED'
            },
            'cutOffResponses': {
                'type': 'checkbox',
                'defaultValue': True,
                'label': 'Truncate responses at head element !!UNIMPLEMENTED'
            },
            'showHTMLComments': {
                'type': 'checkbox',
                'defaultValue': True,
                'label': 'Include HTML comments found in response in markdown',
            },
            'showInlineJS': {
                'type': 'checkbox',
                'defaultValue': True,
                'label': 'Include Inline JavaScript found in responses in markdown',
            },
            'startStopMonitor': {
                'type': 'button',
                'displayText': 'Start Monitoring',
                'label': 'SiteMap Monitor:',
                'listener': self.toggleMonitoring,
                'hasTextField': False
            },
        }
        
        # Create settings UI
        self._create_settings_ui()
        
        # Add tab to Burp UI
        callbacks.addSuiteTab(self)
        
        print("Sitemap to Markdown extension loaded successfully!")

 

    def getTabCaption(self):
        return "BurpSidian"
    
    def getUiComponent(self):
        return self.settingsPanel
    
    def toggleMonitoring(self, event):
        button = event.getSource()
        
        if not self.monitoring:
            # Start monitoring
            self.monitoring = True
            button.setText("Stop Monitoring")
            self.monitorThread = threading.Thread(target=self._monitor_sitemap)
            self.monitorThread.start()
            print("Monitoring started.")
        else:
            # Stop monitoring
            self.monitoring = False
            button.setText("Start Monitoring")
            print("Monitoring stopped.")
    
    def _monitor_sitemap(self):
        seen_urls = set()
        print("monitoring...")
        while self.monitoring:
            try:
                siteMap = self._callbacks.getSiteMap('https://ginandjuice.shop/')
                for entry in siteMap:
                    url = entry.getUrl().toString()
                    if url not in seen_urls:
                        seen_urls.add(url)
                        requestInfo = self._helpers.analyzeRequest(entry.getHttpService(), entry.getRequest())
                        method = requestInfo.getMethod()

                        response = entry.getResponse()
                        status = "No response"
                        if response:
                            responseInfo = self._helpers.analyzeResponse(response)
                            status = responseInfo.getStatusCode()
                            print("[NEW] " + method + " " + url + " - " + str(status))
                            # create new md files
            
            except Exception as e:
                print("Error in monitoring loop:")

            time.sleep(5)  # Avoid spinning too fast
    
    def _create_settings_ui(self):
        self.settingsPanel = JPanel()
        self.settingsPanel.setLayout(GridBagLayout())

        gbc = GridBagConstraints()
        gbc.insets = Insets(10, 10, 10, 10)
        gbc.anchor = GridBagConstraints.WEST

        row = 0
        #generate UI
        for item in self.settingsElements:
            
            gbc.gridy = row
            elItem = self.settingsElements[item]
            if elItem['type'] == 'button':
                
                label = JLabel(elItem['label'])
                btn = JButton(elItem['displayText'])
                txtField = None
                btn.addActionListener(elItem['listener'])

                self.settingsPanel.add(label, gbc)
                self.settingsPanel.add(btn, gbc)
                if elItem['hasTextField']:
                    txtField = JTextField(30)
                    txtField.setText(elItem['txtFieldDefaultValue'])
                    txtField.setEnabled(elItem['txtFieldEnabled'])
                    self.settingsPanel.add(txtField, gbc)
            elif elItem['type'] == 'checkbox':
                checkbox = JCheckBox(elItem['label'], elItem['defaultValue'])
                self.settingsPanel.add(checkbox, gbc)
            elif elItem['type'] == 'txtField':
                label = JLabel(elItem['label'])
                txtField = JTextField(30)
                self.settingsPanel.add(label, gbc)
                self.settingsPanel.add(txtField, gbc)
            else:
                None
            row+=1
        
        
        

    def _browse(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)

        if chooser.showOpenDialog(self.settingsPanel) == JFileChooser.APPROVE_OPTION:
            
            selected_dir = chooser.getSelectedFile().getAbsolutePath()
            self._output_dir_field.setText(selected_dir)
            print("Selected directory: " + selected_dir)
    
# 1. add method to above class
#   This is the login
# 2. add the thing you want to use that logic
#   i.e. a button
# 3. create a listener for the thing from 2
#   shown below
# 4. Wire the save button to use the newly created listener
#   element.addActionListener(self._method)
class BrowseDirectoryListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender  # Store reference to the main extension
    
    def actionPerformed(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        
        # Set the current directory to what's in the text field
        current_dir = self._extender._output_dir_field.getText()
        if current_dir:
            chooser.setCurrentDirectory(File(current_dir))
        
        if chooser.showOpenDialog(self._extender.settingsPanel) == JFileChooser.APPROVE_OPTION:
            selected_dir = chooser.getSelectedFile().getAbsolutePath()
            self._extender._output_dir_field.setText(selected_dir)
            print("Selected directory: " + selected_dir)

        