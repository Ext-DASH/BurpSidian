from burp import IBurpExtender, ITab

from javax.swing import JPanel, JLabel, JTextField, JCheckBox, JButton, JFileChooser, JScrollPane, JTextArea, JComboBox, JSpinner, SpinnerNumberModel, JOptionPane
from javax.swing.border import TitledBorder
from java.awt import GridBagLayout, GridBagConstraints, Insets, FlowLayout, BorderLayout
from java.awt.event import ActionListener
from java.io import File
import java.net.URL

import re
import traceback
import json
import os
import threading
import time

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.loggedKeys = set()

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        self.monitoring = False  # Flag to control monitoring loop
        self.monitorThread = None  # Thread placeholder

        callbacks.setExtensionName("BurpSidian")
        
        # base settings and elements
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
                'txtFieldName': 'outputDirTxt',
                'txtFieldEnabled': False
            },
            'startStopMonitor': {
                'type': 'button',
                'displayText': 'Start Monitoring',
                'label': '',
                'listener': self.toggleMonitoring,
                'hasTextField': False
            },
        }
        # Create settings UI
        self._create_settings_ui()
        # Add tab to Burp UI
        callbacks.addSuiteTab(self)

        print("BurpSidian loaded successfully!")

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
        seenUrls = set()
        
        print("monitoring...")
        while self.monitoring:
            try:

                print("-----------------------------------")
                siteMap = self._callbacks.getSiteMap(None)
                for urlObj in siteMap:
                    baseUrl = urlObj.getProtocol() + "://" + urlObj.getHost()
                    if urlObj.getPort() not in (80, 443):
                        baseUrl += ":" + str(urlObj.getPort())
                    javaUrl = java.net.URL(baseUrl)
                    if self._callbacks.isInScope(javaUrl):
                        siteMap = self._callbacks.getSiteMap(baseUrl)

                        for entry in siteMap:
                            url = entry.getUrl()
                            path = url.getPath()

                            key = baseUrl + path
                            safePath = path.strip('/').replace('/', '_')
                            if not safePath:
                                safePath = 'Home'
                            safeFileName = re.sub(r'[^a-zA-Z0-9_\-]', '_', safePath)
                            #if new url
                            if key not in seenUrls:
                                isUpdate = False
                                response = entry.getResponse()
                                if response: 
                                    resInfo = self._helpers.analyzeResponse(response)
                                    if resInfo.getStatusCode() != 404:
                                        self.createMd(key, entry, response, url, path, safePath, safeFileName, isUpdate)
                                        seenUrls.add(key)
                            else:
                                print('key: ' + key + " is in seenUrls")
                                #if not new url, update params
                                isUpdate = True
                                self.createMd(key, entry, response, url, path, safePath, safeFileName, isUpdate)
            except Exception as e:
                print("Error in monitoring loop:")
                print(e)
                traceback.print_exc()
            time.sleep(5)  # Avoid spinning too fast
    
    def createMd(self, key, entry, response, url, path, safePath, safeFileName, isUpdate):
        folderPath = self.settingsElements['outputDirTxt'].getText()
        os.chdir(folderPath)

        resourceExt = ('.jpg', '.jpeg', '.png', '.gif', '.svg', '.css', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.otf', '.js')
        #if url doesn't end with (resource extension) and has not been created
        if not key.endswith(resourceExt) and safeFileName not in self.loggedKeys:
            #make a valid name for the md file
            key = key.strip('/')

            #get request info
            requestInfo = self._helpers.analyzeRequest(entry.getHttpService(), entry.getRequest())
            method = requestInfo.getMethod()
            params = requestInfo.getParameters()

            # get headers list
            headers = requestInfo.getHeaders()

            # create body
            body_offset = requestInfo.getBodyOffset()
            body_bytes = entry.getRequest()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)

            # Combine headers and body into full HTTP request
            full_request = "\r\n".join(headers) + "\r\n\r\n" + body
            
            #analyze response
            responseInfo = self._helpers.analyzeResponse(response)

            # Headers (Java List)
            responseHeaders = responseInfo.getHeaders()
            
            # Body
            res_body_offset = responseInfo.getBodyOffset()
            res_body_bytes = response[res_body_offset:]
            resBody = self._helpers.bytesToString(res_body_bytes)

            #check if content type is text/html
            isHtmlContentType = any("content-type:" in h.lower() and "text/html" in h.lower() for h in responseHeaders)

            trimmedRes = ''
            trimmedBody = ''
            if isHtmlContentType:
                #if it is text/html, find </head> and truncate
                resClosingHeadIdx = resBody.lower().find("</head>")
                if resClosingHeadIdx != -1:
                    trimmedRes = resBody[:resClosingHeadIdx + len("</head>")] + '\r\n' + "[TRUNCATED]"
                    trimmedBody = resBody[resClosingHeadIdx + len("</head>"):]
                else:
                    trimmedBody = resBody
                    trimmedRes = resBody
            #find comments, js, and forms in response body
            comments = re.findall(r'<!--(.*?)-->', resBody, re.DOTALL | re.IGNORECASE)
            inlineJS = re.findall(r'<script.*?>(.*?)</script>', trimmedBody, re.DOTALL | re.IGNORECASE)
            forms = re.findall(r'<form.*?>(.*?)</form>', resBody, re.DOTALL | re.IGNORECASE)
            #Create markdown
            print("creating markdown for key: " + key)
            #below needs refactor
            lines = ''
            with open(safeFileName + ' - ' + method + '.md', "a") as f:  
                #link, desc, inputs header
                lines += ('\r\n'+"#### Link: " + key + '\r\n\r\n'+'#### Description: '+'\r\n'+'UPDATE\r\n\r\n---\r\n\r\n#### Inputs:\r\n')
                #inputs
                paramTypes = {0: '(URL)\r\n', 1: '(BODY)\r\n', 2: '(COOKIE)\r\n'}

                for param in params:
                    lines += ('- ' + param.getName() + ' ' + paramTypes.get(param.getType(), '(UNKNOWN)\r\n'))
                #sample req and res
                lines += ("\r\n---\r\n" \
                "#### Sample Request:\r\n\r\n" \
                "```HTTP\r\n"+full_request+"\r\n\r\n```\r\n\r\n---\r\n\r\n" \
                "#### Sample Response:\r\n\r\n" \
                "```HTTP\r\n\r\n" + "\r\n".join(responseHeaders)+"\r\n\r\n"+trimmedRes+"\r\n" \
                "```\r\n\r\n---\r\n\r\n")
                #comments
                if comments:
                    lines += ('#### Found Comments:\r\n\r\n')
                    for cmnt in comments:
                        lines += ('```HTML' + '\r\n' + '<!-- \r\n' + cmnt.strip() + '\r\n -->' + '\r\n```\r\n\r\n')
                    lines += ('\r\n---\r\n')
                #inlineJS
                if inlineJS:
                    lines += ('#### Found Scripts:\r\n\r\n')
                    for script in inlineJS:
                        lines += ('```HTML' + '\r\n' + '<script>\r\n' + script.strip() + '\r\n</script>' + '\r\n```\r\n\r\n')
                    lines += ('\r\n---\r\n')
                #forms
                if forms:
                    lines += ('#### Found Forms:\r\n\r\n')
                    for form in forms:
                        lines += ('```HTML' + '\r\n' + '<form>\r\n' + form.strip() + '\r\n</form>' + '\r\n```\r\n\r\n')
                    lines += ('\r\n---\r\n')
                
                f.write(lines)
            #mark key as logged
            self.loggedKeys.add(key)
        if key.endswith('.js') and key not in self.loggedKeys:
            # check for "Static JS Includes" file
            fileName = "Static JS Inclusions.md"
            with open(fileName, "a") as f:
                f.write('\r\n')
                f.write('- ')
                f.write(key)
            self.loggedKeys.add(safeFileName)

        else:    
            None
    def _create_settings_ui(self):
        self.settingsPanel = JPanel()
        self.settingsPanel.setLayout(GridBagLayout())

        gbc = GridBagConstraints()
        gbc.insets = Insets(10, 10, 10, 10)
        gbc.anchor = GridBagConstraints.WEST

        row = 0
        #generate UI For Loop
        for item in self.settingsElements:
            
            gbc.gridy = row
            elItem = self.settingsElements[item]
            if elItem['type'] == 'checkbox':
                checkbox = JCheckBox(elItem['label'], elItem['defaultValue'])
                self.settingsPanel.add(checkbox, gbc)
                self.settingsElements[item] = checkbox
            elif elItem['type'] == 'txtField':
                label = JLabel(elItem['label'])
                txtField = JTextField(30)
                self.settingsPanel.add(label, gbc)
                self.settingsPanel.add(txtField, gbc)
                self.settingsElements[item] = txtField
            elif elItem['type'] == 'button':
                
                label = JLabel(elItem['label'])
                btn = JButton(elItem['displayText'])
                txtField = None
                btn.addActionListener(elItem['listener'])

                self.settingsPanel.add(label, gbc)
                self.settingsPanel.add(btn, gbc)
                self.settingsElements[item] = btn
                if elItem['hasTextField']:
                    txtField = JTextField(30)
                    txtField.setText(elItem['txtFieldDefaultValue'])
                    txtField.setEnabled(elItem['txtFieldEnabled'])
                    self.settingsPanel.add(txtField, gbc)
                    self.settingsElements['outputDirTxt'] = txtField
            else:
                None
            row+=1

    def _browse(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        if chooser.showOpenDialog(self.settingsPanel) == JFileChooser.APPROVE_OPTION:
            selected_dir = chooser.getSelectedFile().getAbsolutePath()
            self.settingsElements['outputDirTxt'].setText(selected_dir)
            print("Selected directory: " + selected_dir)

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