from burp import IBurpExtender
from burp import IExtensionStateListener
from burp import ITab

# no multiprocessing available in Jython
# solution adapted from: https://stackoverflow.com/questions/11460310/how-could-i-use-jython-threads-as-they-were-java-threads
import threading
import time
import base64
import re
import urlparse
from HTMLParser import HTMLParser # sometimes emails are HTML encoded
import cgi # use this to generate an HTML encoded version of the test email

# UI import
import javax.swing

# Clipboard
from java.awt.datatransfer import StringSelection
from java.awt.datatransfer import Clipboard
from java.awt import Toolkit

class BurpExtender(IBurpExtender, IExtensionStateListener, ITab):

    def __init__(self):
        self.canceled = False
        self.polltime = 5
        self.outfile = '/tmp/reset-a-tron.txt'
        self.reURLS = 'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        self.parametername = 'token'
        self.testresetemail = '''<!DOCTYPE html>
<html>
<head>
</head>

<body style="font-family: Arial; font-size: 12px;">
<div>
    <p>
        You have requested a password reset, please follow the link below to reset your password.
    </p>
    <p>
        Please ignore this email if you did not request a password change.
    </p>

    <p>
        <a href="https://www.donotzonetransfer.com/reset?{}">
            Follow this link to reset your password.
        </a>
    </p>
</div>
</body>
</html>'''.format(self.parametername + '=' + 'tyfhjgfhjghf6547647fh567r')
        self.htmlparser = HTMLParser()
     
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName('reset-a-tron')
        self.callbacks.registerExtensionStateListener(self)
        self.ccc = self.callbacks.createBurpCollaboratorClientContext()
        self.maildomain = self.ccc.generatePayload(True)
        # prints to std out
        print("[*] Extension loaded")
        self.initUi()
        # add the custom tab to Burp's UI
        self.callbacks.addSuiteTab(self)
        return

    def initUi(self):
        #find and replace Short.MAX_VALUE = 32767
        self.tokenButtonGroup = javax.swing.ButtonGroup()
        self.fileChooser = javax.swing.JFileChooser()
        self.bottomPanel = javax.swing.JPanel()
        self.tokenPanel = javax.swing.JPanel()
        self.paramButton = javax.swing.JRadioButton()
        self.regexButton = javax.swing.JRadioButton()
        self.paramNameTextField = javax.swing.JTextField()
        self.paramNameLabel = javax.swing.JLabel()
        self.regexLabel = javax.swing.JLabel()
        self.regexTextField = javax.swing.JTextField()
        self.controlPanel = javax.swing.JPanel()
        self.pollTimeLabel = javax.swing.JLabel()
        self.fileLabel = javax.swing.JLabel()
        self.pollTimeTextField = javax.swing.JTextField()
        self.outputFileTextField = javax.swing.JTextField()
        self.startButton = javax.swing.JButton(actionPerformed=self.startPolling)
        self.stopButton = javax.swing.JButton(actionPerformed=self.stopPolling)
        self.chooseFileButton = javax.swing.JButton(actionPerformed=self.chooseFile)
        self.copyEmailButton = javax.swing.JButton(actionPerformed=self.copyEmail)
        self.outputPanel = javax.swing.JPanel()
        self.jScrollPane1 = javax.swing.JScrollPane()
        self.outputTextArea = javax.swing.JTextArea()

        self.tokenPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(javax.swing.BorderFactory.createEtchedBorder(), "Token Type"))

        self.tokenButtonGroup.add(self.paramButton)
        self.paramButton.setSelected(True)
        self.paramButton.setText("Link Parameter")

        self.tokenButtonGroup.add(self.regexButton)
        self.regexButton.setText("Email body")

        self.paramNameTextField.setText("token")

        self.paramNameLabel.setText("Name:")

        self.regexLabel.setText("Regex:")

        self.regexTextField.setText('token=(.*?)\&quot')

        self.tokenPanelLayout = javax.swing.GroupLayout(self.tokenPanel)
        self.tokenPanel.setLayout(self.tokenPanelLayout)
        self.tokenPanelLayout.setHorizontalGroup(
            self.tokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(self.tokenPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(self.tokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(self.paramButton)
                    .addComponent(self.regexButton))
                .addGap(40, 40, 40)
                .addGroup(self.tokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(self.tokenPanelLayout.createSequentialGroup()
                        .addComponent(self.regexLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.regexTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 370, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(self.tokenPanelLayout.createSequentialGroup()
                        .addComponent(self.paramNameLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.paramNameTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 370, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(54, 32767))
        )
        self.tokenPanelLayout.setVerticalGroup(
            self.tokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(self.tokenPanelLayout.createSequentialGroup()
                .addGap(23, 23, 23)
                .addGroup(self.tokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(self.paramButton)
                    .addComponent(self.paramNameLabel)
                    .addComponent(self.paramNameTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(55, 55, 55)
                .addGroup(self.tokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(self.regexButton)
                    .addComponent(self.regexLabel)
                    .addComponent(self.regexTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(73, 32767))
        )

        self.controlPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(javax.swing.BorderFactory.createEtchedBorder(), "Control"))

        self.pollTimeLabel.setText("Poll Time:")

        self.fileLabel.setText("Output File:")

        self.pollTimeTextField.setText("5")

        self.outputFileTextField.setText("/tmp/reset-a-tron.txt")

        self.startButton.setText("Start")

        self.stopButton.setText("Stop")
        self.stopButton.setEnabled(False)

        self.chooseFileButton.setText("Choose File")

        self.copyEmailButton.setText("Copy Email")

        self.controlPanelLayout = javax.swing.GroupLayout(self.controlPanel)
        self.controlPanel.setLayout(self.controlPanelLayout)
        self.controlPanelLayout.setHorizontalGroup(
            self.controlPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(self.controlPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(self.controlPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(self.controlPanelLayout.createSequentialGroup()
                        .addComponent(self.fileLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.outputFileTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 310, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(self.chooseFileButton)
                    .addGroup(self.controlPanelLayout.createSequentialGroup()
                        .addComponent(self.pollTimeLabel)
                        .addGap(18, 18, 18)
                        .addComponent(self.pollTimeTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 51, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(self.controlPanelLayout.createSequentialGroup()
                        .addComponent(self.startButton, javax.swing.GroupLayout.PREFERRED_SIZE, 154, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(self.stopButton, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(self.copyEmailButton, javax.swing.GroupLayout.PREFERRED_SIZE, 151, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(53, 32767))
        )
        self.controlPanelLayout.setVerticalGroup(
            self.controlPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(self.controlPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(self.chooseFileButton)
                .addGap(18, 18, 18)
                .addGroup(self.controlPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(self.fileLabel)
                    .addComponent(self.outputFileTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(self.controlPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(self.pollTimeLabel)
                    .addComponent(self.pollTimeTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, 32767)
                .addGroup(self.controlPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(self.startButton)
                    .addComponent(self.stopButton)
                    .addComponent(self.copyEmailButton))
                .addContainerGap())
        )

        self.outputPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(javax.swing.BorderFactory.createEtchedBorder(), "Output"))

        self.jScrollPane1.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER)

        self.outputTextArea.setColumns(20)
        self.outputTextArea.setLineWrap(True)
        self.outputTextArea.setRows(5)
        self.jScrollPane1.setViewportView(self.outputTextArea)

        self.outputPanelLayout = javax.swing.GroupLayout(self.outputPanel)
        self.outputPanel.setLayout(self.outputPanelLayout)
        self.outputPanelLayout.setHorizontalGroup(
            self.outputPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(self.jScrollPane1)
        )
        self.outputPanelLayout.setVerticalGroup(
            self.outputPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(self.jScrollPane1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 487, 32767)
        )

        self.bottomPanelLayout = javax.swing.GroupLayout(self.bottomPanel)
        self.bottomPanel.setLayout(self.bottomPanelLayout)
        self.bottomPanelLayout.setHorizontalGroup(
            self.bottomPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(self.bottomPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(self.bottomPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(self.outputPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, 32767)
                    .addGroup(self.bottomPanelLayout.createSequentialGroup()
                        .addComponent(self.tokenPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(1, 1, 1)
                        .addComponent(self.controlPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 8, 32767)))
                .addContainerGap())
        )
        self.bottomPanelLayout.setVerticalGroup(
            self.bottomPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(self.bottomPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(self.bottomPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, False)
                    .addComponent(self.tokenPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, 32767)
                    .addComponent(self.controlPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, 32767))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self.outputPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, 32767)
                .addContainerGap())
        )
        
        # leave the next two lines
        self.bottomPanel.getAccessibleContext().setAccessibleName("Polling")
        self.callbacks.customizeUiComponent(self.bottomPanel)

    def startPolling(self, event):
        self.canceled = False
        self.polltime = int(self.pollTimeTextField.getText())
        self.outfile = self.outputFileTextField.getText()
        self.parametername = self.paramNameTextField.getText()
        # prints to UI
        self.printToUi("[*] Email payload: [anything]@{}".format(self.maildomain))
        #self.printToUi("[*] Polling at {} second intervals".format(self.polltime))
        htmlescapedbody = cgi.escape(self.testresetemail, quote=True)
        self.printToUi("[*] sendemail command:\n\nsendemail -f user@localhost -u test -m '{}' -o tls=no -t test@{} -s {}".format(htmlescapedbody, self.maildomain, self.maildomain))
        self.t = threading.Thread(target=self.pollCollab, args = (self.ccc, self.maildomain))
        self.t.daemon = True
        self.t.start()
        self.startButton.setEnabled(False)
        self.stopButton.setEnabled(True)

    def printToUi(self, s):
        self.outputTextArea.append(s + '\n')

    # next two methods implement ITab
    def getTabCaption(self):
        return "Reset-a-tron"
    
    def getUiComponent(self):
        return self.bottomPanel

    # polling logic here
    def pollCollab(self, collabClientContext, maildomain):
        while not self.canceled:
            try:
                interactions = collabClientContext.fetchCollaboratorInteractionsFor(maildomain)
                if interactions:
                    pyinteractions = list(interactions) # cast Java list to Python list
                    for i,item in enumerate(pyinteractions):
                        try:
                            msg = item.getProperty("conversation")
                            if msg:
                                self.printToUi("[*] Received email.")
                                b64decodedmsg = base64.b64decode(msg)
                                print("[*] Email contents:\n" + b64decodedmsg)
                                if self.paramButton.isSelected():
                                    htmldecodedmsg = self.htmlparser.unescape(b64decodedmsg)
                                    urllist  = re.findall(self.reURLS, htmldecodedmsg)
                                    for i,url in enumerate(urllist):
                                        try:
                                            parsed = urlparse.urlparse(url)
                                            parametervalue =  str(urlparse.parse_qs(parsed.query)[self.parametername][0])
                                            self.printToUi('[*] URL search located {} parameter value {}. Saving to file.'.format(self.parametername, parametervalue))
                                            with open(self.outfile, 'a') as f:
                                                f.write(parametervalue + '\n')
                                        except Exception, e:
                                            self.printToUi('[!] URL parsing exception: {}'.format(e))
                                            pass
                                else:
                                    try:
                                        regex = self.regexTextField.getText()
                                        matchlist = re.findall(regex, b64decodedmsg)
                                        for item in matchlist:
                                            self.printToUi('[*] RegEx located {}. Saving to file.'.format(item))
                                            with open(self.outfile, 'a') as f:
                                                f.write(item + '\n')
                                    except Exception, e:
                                        self.printToUi('[!] Regex exception: {}'.format(e))
                        except Exception, e:
                            self.printToUi('[!] Exception: {}'.format(e))
                            pass
                time.sleep(self.polltime)
            except threading.InterruptedException:
                self.canceled = True
        return

    def extensionUnloaded(self):
        print("[!] Extension unloaded - terminating thread.")
        self.canceled = True
        try:
            self.t.join()
            print("[*] Thread isAlive(): " + str(self.t.isAlive()))
        except:
            pass
        return

    def stopPolling(self, event):
        self.canceled = True
        try:
            self.t.join()
            self.printToUi("[*] Thread isAlive(): " + str(self.t.isAlive()))
        except:
            pass
        self.startButton.setEnabled(True)
        self.stopButton.setEnabled(False)
        return

    def chooseFile(self, event):
        retval = self.fileChooser.showOpenDialog(self.bottomPanel)
        if (retval == javax.swing.JFileChooser.APPROVE_OPTION):
            self.outfile = str(self.fileChooser.getSelectedFile())
            self.outputFileTextField.setText(self.outfile)

    def copyEmail(self, event):
        toolkit = Toolkit.getDefaultToolkit()
        clipboard = toolkit.getSystemClipboard()
        clipboard.setContents(StringSelection(self.maildomain), None)
        self.printToUi('[*] Domain copied to clipboard')
