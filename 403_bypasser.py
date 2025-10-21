# -*- coding: utf-8 -*-
# Burp 403 Bypasser - Standalone UI (Jython)
# Drop this file into Burp Extender (Python/Jython). It runs as a self-contained tool
# with a Swing UI inside the Extender tab. It does NOT rely on Burp Pro active scanner.
# Features:
# - Runs standalone worker thread to test path and header payloads against 403 responses
# - Safe scope checking and rate limiting
# - Start/Stop controls, payload toggles, and a results table
# - Uses Burp helpers to build requests (no brittle string.replace)

from burp import IBurpExtender, ISessionHandlingAction, IHttpRequestResponse, ITab, IHttpListener, IContextMenuFactory
from java.io import PrintWriter
from javax import swing
from javax.swing import SwingUtilities, BorderFactory, JTabbedPane, JToolBar, JButton, JLabel
from java.lang import Runnable
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Dimension, Font
from java.awt.event import ActionListener
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener
from threading import Thread, Event
import time
import traceback
from javax.swing.text import SimpleAttributeSet, StyleConstants, StyledDocument

class FuncRunnable(Runnable):
    def __init__(self, fn):
        self.fn = fn
    def run(self):
        try:
            self.fn()
        except Exception:
            try:
                import sys, traceback
                sys.stderr.write("[FuncRunnable] exception:\n")
                traceback.print_exc()
            except:
                pass

class BypassWorker(Thread):
    def __init__(self, ext):
        Thread.__init__(self)
        self.ext = ext
        # worker uses the same stop_event object stored on extender
        self.stop_event = ext.stop_event

    def stop(self):
        try:
            self.stop_event.set()
        except:
            pass

    def run(self):
        try:
            self.ext.stdout.println("[BypassWorker] started")
            while not self.stop_event.is_set():
                job = self.ext.get_next_job()
                if job is None:
                    time.sleep(0.2)
                    continue
                baseRequestResponse = job.req
                # respect scope
                url = self.ext._helpers.analyzeRequest(baseRequestResponse).getUrl()
                # skip only if not ignoring scope and URL is out of scope
                try:
                    ignore_scope = getattr(self.ext, 'ignore_scope_checkbox', None) and self.ext.ignore_scope_checkbox.isSelected()
                except:
                    ignore_scope = False
                if (not ignore_scope) and (not self.ext._callbacks.isInScope(url)):
                    self.ext.stdout.println("[BypassWorker] skipped (out of scope): %s" % url)
                    continue
                # optionally report source for visibility
                try:
                    src = job.source
                except:
                    src = "unknown"
                self.ext.stdout.println("[BypassWorker] processing (source=%s): %s" % (src, url))

                self.try_bypass(baseRequestResponse)
                # respect rate limit
                time.sleep(1.0 / max(0.1, float(self.ext.rate_limit)))

            self.ext.stdout.println("[BypassWorker] stopped")
        except Exception as e:
            self.ext.stderr.println("[BypassWorker] exception: %s" % str(e))
            self.ext.stderr.println(traceback.format_exc())

    def try_bypass(self, baseRequestResponse):
        try:
            helpers = self.ext._helpers
            analyzed = helpers.analyzeRequest(baseRequestResponse)
            url = analyzed.getUrl()
            path = url.getPath() or "/"
            if path == "":
                path = "/"

            # only attempt when original response was 403
            resp_code = helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode()
            if resp_code != 403:
                return

            # prepare canonical pieces
            orig_headers = list(analyzed.getHeaders())
            body_bytes = baseRequestResponse.getRequest()[analyzed.getBodyOffset():]

            # normalize path
            clean_path = path.rstrip('/') if path != '/' else '/'
            last_segment = clean_path.split('/')[-1] if clean_path != '/' else ''

            path_payloads = []
            if last_segment:
                path_payloads = [
                    "%2e/" + last_segment,
                    last_segment + "/.",
                    "./" + last_segment + "/./",
                    last_segment + "%20/",
                    "%20" + last_segment + "%20/",
                    last_segment + "..;/",
                    last_segment + "?",
                    last_segment + "??",
                    "/" + last_segment + "//",
                    last_segment + "/",
                    last_segment + "/.randomstring"
                ]

            header_payloads = [
                ("X-Original-URL", path + "4nyth1ng"),
                ("X-Rewrite-URL", path),
                ("Referer", "/" + last_segment if last_segment else "/"),
                ("X-Custom-IP-Authorization", "127.0.0.1"),
                ("X-Originating-IP", "127.0.0.1"),
                ("X-Forwarded-For", "127.0.0.1"),
                ("X-Remote-IP", "127.0.0.1"),
                ("X-Client-IP", "127.0.0.1"),
                ("X-Host", "127.0.0.1"),
                ("X-Forwarded-Host", "127.0.0.1")
            ]

            results = []

            # path payloads
            for p in path_payloads:
                if self.ext.stop_event.is_set():
                    return
                # build new headers by replacing request line
                new_headers = list(orig_headers)
                first = new_headers[0]
                try:
                    method, req_path, proto = first.split(' ', 2)
                except ValueError:
                    # malformed request line, skip
                    continue
                parent = '/'.join(req_path.rstrip('/').split('/')[:-1])
                if parent == '':
                    parent = '/'
                # ensure we combine without producing duplicate slashes
                if parent == '/':
                    new_path = '/' + p
                else:
                    new_path = parent.rstrip('/') + '/' + p
                new_headers[0] = "%s %s %s" % (method, new_path, proto)

                new_req = helpers.buildHttpMessage(new_headers, body_bytes)
                rr = self.ext._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_req)
                code = helpers.analyzeResponse(rr.getResponse()).getStatusCode()
                if code == 200:
                    results.append(("path", new_path, code, rr))

            # header payloads
            for hname, hval in header_payloads:
                if self.ext.stop_event.is_set():
                    return
                new_headers = [h for h in orig_headers if not h.lower().startswith(hname.lower() + ":")]
                new_headers.append("%s: %s" % (hname, hval))
                new_req = helpers.buildHttpMessage(new_headers, body_bytes)
                rr = self.ext._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_req)
                code = helpers.analyzeResponse(rr.getResponse()).getStatusCode()
                if code == 200:
                    results.append(("header", "%s: %s" % (hname, hval), code, rr))

            # filter false positives: compare response length vs baseline, or keywords
            baseline_len = len(baseRequestResponse.getResponse())
            for kind, payload, code, rr in results:
                resp = rr.getResponse()
                resp_len = len(resp)
                if resp_len == baseline_len:
                    confidence = "Low (same length)"
                else:
                    confidence = "High"
                # pass the rr object so the UI can show request/response for that result
                self.ext.add_result(url.toString(), kind, payload, code, confidence, rr)

        except Exception as e:
            self.ext.stderr.println("[try_bypass] exception: %s" % e)
            self.ext.stderr.println(traceback.format_exc())


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        # standard boilerplate
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("403 Bypasser - Standalone UI")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        # UI state
        self.rate_limit = 5.0  # requests per second (default)
        self.jobs = []
        self.worker = None
        self.stop_event = Event()

        # build UI synchronously so Burp registers the suite tab immediately
        self.build_ui()

        # register context menu so user can still right-click -> "Send to 403 Bypasser"
        try:
            callbacks.registerContextMenuFactory(ContextMenuFactory(self))
            self.stdout.println("[Extender] context menu registered: Send to 403 Bypasser")
        except:
            try:
                self.stdout.println("[Extender] failed to register context menu")
            except:
                pass

        # register a basic session handler action if you want to auto-add requests
        # callbacks.registerSessionHandlingAction(MySessionHandler(self))

        # also add a small note to stdout
        self.stdout.println("403 Bypasser loaded. Open Extender -> 403 Bypasser tab.")

    # UI helpers
    def build_ui(self):
        self.panel = swing.JPanel(BorderLayout())

        # top controls
        controls = swing.JPanel()
        controls.setLayout(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.weightx = 0.0

        self.start_btn = swing.JButton('Start', actionPerformed=self.start_clicked)
        controls.add(self.start_btn, gbc)
        gbc.gridx += 1
        self.stop_btn = swing.JButton('Stop', actionPerformed=self.stop_clicked)
        self.stop_btn.setEnabled(False)
        controls.add(self.stop_btn, gbc)
        gbc.gridx += 1
        controls.add(swing.JLabel('Rate (req/s):'), gbc)
        gbc.gridx += 1
        self.rate_field = swing.JTextField(str(self.rate_limit), columns=5)
        controls.add(self.rate_field, gbc)
        gbc.gridx += 1
        # ignore scope when processing queued jobs (off by default)
        self.ignore_scope_checkbox = swing.JCheckBox('Ignore scope for queued jobs', selected=False)
        controls.add(self.ignore_scope_checkbox, gbc)
        gbc.gridx += 1
        # removed "Auto-enqueue" and "Enqueue Selected Request" UI elements per request;
        # keep a small spacer so layout remains stable
        controls.add(swing.JLabel(""), gbc)
        gbc.gridx += 1

        # --- QUEUE UI (top) ---
        queue_cols = ['Queued URL', 'Method', 'Status', 'Source']
        self.queue_model = DefaultTableModel([], queue_cols)
        self.queue_table = swing.JTable(self.queue_model)
        self.queue_table.setPreferredScrollableViewportSize(Dimension(800, 80))
        queue_scroll = swing.JScrollPane(self.queue_table)

        # nice small label that shows selected queue URL quickly
        self.queue_label = swing.JLabel("Queued URL: <none>")
        self.queue_label.setPreferredSize(Dimension(800, 20))

        # results table (middle, primary view) — make this smaller so bottom gets more space
        cols = ['URL', 'Type', 'Payload', 'HTTP', 'Confidence']
        self.table_model = DefaultTableModel([], cols)
        self.result_table = swing.JTable(self.table_model)
        # reduce results viewport height
        self.result_table.setPreferredScrollableViewportSize(Dimension(800, 140))
        result_scroll = swing.JScrollPane(self.result_table)

        # ------------ bottom panes: use Burp's message editors for exact Repeater look ------------
        # Request editor (editable) and Response editor (read-only) come from Burp callbacks
        try:
            self.reqEditor = self._callbacks.createMessageEditor(None, True)   # editable
            req_comp = self.reqEditor.getComponent()
        except Exception:
            # fallback to plain text pane if createMessageEditor unavailable
            self.reqEditor = None
            req_comp = self.request_pane_raw

        try:
            self.respEditor = self._callbacks.createMessageEditor(None, False)  # read-only
            resp_comp = self.respEditor.getComponent()
        except Exception:
            self.respEditor = None
            resp_comp = self.response_pane_raw

        # wrap the editor components (these include Burp's internal UI and tabs)
        req_scroll = swing.JScrollPane(req_comp)
        resp_scroll = swing.JScrollPane(resp_comp)

        # request toolbar (mimic Repeater) — simplified: only label (remove arrows / copy / send)
        req_toolbar = JToolBar()
        req_toolbar.setFloatable(False)
        req_toolbar.add(JLabel("Request"))
        req_toolbar.add(swing.JLabel("  "))
        # removed nav/copy/send buttons per your request

        request_container = swing.JPanel(BorderLayout())
        request_container.add(req_toolbar, BorderLayout.NORTH)
        request_container.add(req_scroll, BorderLayout.CENTER)
        request_container.setBorder(BorderFactory.createEmptyBorder(2,2,2,2))

        # response toolbar — simplified: only label
        resp_toolbar = JToolBar()
        resp_toolbar.setFloatable(False)
        resp_toolbar.add(JLabel("Response"))
        resp_toolbar.add(swing.JLabel("  "))
        # removed nav/copy/render buttons per your request

        response_container = swing.JPanel(BorderLayout())
        response_container.add(resp_toolbar, BorderLayout.NORTH)
        response_container.add(resp_scroll, BorderLayout.CENTER)
        response_container.setBorder(BorderFactory.createEmptyBorder(2,2,2,2))

        rr_split = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT, request_container, response_container)
        rr_split.setResizeWeight(0.5)
        rr_split.setPreferredSize(Dimension(800, 300))
        try:
            rr_split.setDividerLocation(380)
        except:
            pass

        # footer removed (no footer, keep only request/response split)
        bottom_panel = swing.JPanel(BorderLayout())
        bottom_panel.add(rr_split, BorderLayout.CENTER)

        # assemble center panel
        center_panel = swing.JPanel()
        center_panel.setLayout(BorderLayout())
        top_panel = swing.JPanel(BorderLayout())
        top_panel.add(self.queue_label, BorderLayout.NORTH)
        top_panel.add(queue_scroll, BorderLayout.CENTER)

        mid_split = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT, result_scroll, bottom_panel)
        mid_split.setResizeWeight(0.75)   # keep third smaller as requested
        try:
            mid_split.setDividerLocation(180)
        except:
            pass

        center_panel.add(top_panel, BorderLayout.NORTH)
        center_panel.add(mid_split, BorderLayout.CENTER)
        self.panel.add(controls, BorderLayout.NORTH)
        self.panel.add(center_panel, BorderLayout.CENTER)

        # keep a list of result objects so we can show details when a row is selected
        self.result_items = []

        # wire up queue selection to use message editor when available
        # update legacy reference so older code that expects self.request_pane still works:
        if self.reqEditor is not None:
            self.request_pane = self.reqEditor
        else:
            self.request_pane = self.request_pane_raw

        # add the panel to Burp's Extender tab
        self._callbacks.addSuiteTab(Tab('403 Bypasser', self.panel))

        # selection listener for queue table -> show raw request and update queue label
        class QueueSelectionListener(ListSelectionListener):
            def __init__(self, ext, table, req_view, queue_label):
                self.ext = ext
                self.table = table
                self.req_view = req_view
                self.queue_label = queue_label
            def valueChanged(self, event):
                try:
                    sel = self.table.getSelectedRow()
                    if sel >= 0 and sel < len(self.ext.jobs):
                        job = self.ext.jobs[sel]
                        try:
                            raw_bytes = job.req.getRequest()
                            raw = self.ext._helpers.bytesToString(raw_bytes) if raw_bytes else "<no request>"
                        except:
                            raw_bytes = None
                            raw = "<no request>"
                        # Support either Burp message editor (setMessage) or plain text pane (setText)
                        try:
                            if hasattr(self.req_view, 'setMessage'):
                                # req_view is a Burp message editor
                                try:
                                    self.req_view.setMessage(raw_bytes, True)
                                except:
                                    # some message editors expect bytes; fall back to string conversion
                                    self.req_view.setMessage(self.ext._helpers.stringToBytes(raw if raw else ""), True)
                            else:
                                self.req_view.setText(raw)
                        except:
                            try:
                                self.req_view.setText(raw)
                            except:
                                pass
                        try:
                            url = self.ext._helpers.analyzeRequest(job.req).getUrl().toString()
                        except:
                            url = "<unknown>"
                        self.queue_label.setText("Queued URL: %s" % url)
                except:
                    pass

        self.queue_table.getSelectionModel().addListSelectionListener(QueueSelectionListener(self, self.queue_table, self.request_pane, self.queue_label))

        # selection listener for results -> populate Burp message editors (exact Repeater look/behaviour)
        class ResultSelectionListener(ListSelectionListener):
            def __init__(self, ext, table, reqEditor, respEditor):
                self.ext = ext
                self.table = table
                self.reqEditor = reqEditor
                self.respEditor = respEditor

            def valueChanged(self, event):
                try:
                    sel = self.table.getSelectedRow()
                    if sel >= 0 and sel < len(self.ext.result_items):
                        rr = self.ext.result_items[sel]
                        try:
                            req_bytes = rr.getRequest()
                            resp_bytes = rr.getResponse()
                            # Use Burp message editors when available (they provide the Repeater UI)
                            if self.reqEditor:
                                try:
                                    self.reqEditor.setMessage(req_bytes, True)
                                except:
                                    # fallback: set text if only a component is present
                                    try:
                                        comp = self.reqEditor.getComponent()
                                        if hasattr(comp, 'setText'):
                                            comp.setText(self.ext._helpers.bytesToString(req_bytes) if req_bytes else "")
                                    except:
                                        pass
                            else:
                                try:
                                    self.ext.request_pane.setText(self.ext._helpers.bytesToString(req_bytes) if req_bytes else "")
                                except:
                                    pass

                            if self.respEditor:
                                try:
                                    self.respEditor.setMessage(resp_bytes, False)
                                except:
                                    try:
                                        comp = self.respEditor.getComponent()
                                        if hasattr(comp, 'setText'):
                                            comp.setText(self.ext._helpers.bytesToString(resp_bytes) if resp_bytes else "")
                                    except:
                                        pass
                            else:
                                try:
                                    self.ext.response_pane.setText(self.ext._helpers.bytesToString(resp_bytes) if resp_bytes else "")
                                except:
                                    pass

                        except Exception:
                            try:
                                if self.reqEditor:
                                    self.reqEditor.setMessage(None, True)
                                if self.respEditor:
                                    self.respEditor.setMessage(None, False)
                            except:
                                pass
                except:
                    pass

        # wire up selection listener using the editors (may be None if fallback)
        self.result_table.getSelectionModel().addListSelectionListener(
            ResultSelectionListener(self, self.result_table, getattr(self, 'reqEditor', None), getattr(self, 'respEditor', None)))

    # add job (called from UI / context menu / proxy listener)
    def enqueue_request(self, baseRequestResponse, source='UI'):
        # store request wrapped in a Job; worker will pop
        self.jobs.append(Job(baseRequestResponse, source))
        # update queue UI on EDT
        def do_add():
            try:
                helpers = self._helpers
                analyzed = helpers.analyzeRequest(baseRequestResponse)
                method = analyzed.getMethod()
                url = analyzed.getUrl().toString()
                resp = baseRequestResponse.getResponse()
                status = str(helpers.analyzeResponse(resp).getStatusCode()) if resp else ''
                self.queue_model.addRow([url, method, status, source])
            except:
                pass
        SwingUtilities.invokeLater(FuncRunnable(do_add))

    def get_next_job(self):
        if not self.jobs:
            return None
        job = self.jobs.pop(0)  # Job instance
        # remove row 0 from UI queue model on EDT
        def do_remove():
            try:
                if self.queue_model.getRowCount() > 0:
                    self.queue_model.removeRow(0)
            except:
                pass
        SwingUtilities.invokeLater(FuncRunnable(do_remove))
        return job

    # UI button callbacks
    def start_clicked(self, event):
        try:
            self.rate_limit = float(self.rate_field.getText())
        except Exception:
            self.rate_limit = 5.0
            self.rate_field.setText(str(self.rate_limit))

        if self.worker and getattr(self.worker, 'isAlive', lambda: False)():
            self.stdout.println('[UI] worker already running')
            return
        # create a fresh stop_event for this run so previous state doesn't leak
        self.stop_event = Event()
        self.worker = BypassWorker(self)
        # optional: run as daemon so it won't block shutdown
        try:
            self.worker.setDaemon(True)
        except:
            pass
        self.worker.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_clicked(self, event):
        if self.worker:
            try:
                self.worker.stop()
                self.worker.join(1.0)
                self.worker = None
            except:
                pass
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def enqueue_clicked(self, event):
        # enqueue functionality removed — kept as a no-op to preserve UI integrity
        try:
            self.stdout.println('[UI] Enqueue selected request: disabled by configuration')
        except:
            pass
        return

    def add_result(self, url, kind, payload, code, confidence, http_rr):
        # called by worker thread — must update Swing on EDT
        def do_add():
            try:
                self.table_model.addRow([url, kind, payload, str(code), confidence])
                # keep parallel array of IHttpRequestResponse objects for detail display
                self.result_items.append(http_rr)
            except:
                pass
        SwingUtilities.invokeLater(FuncRunnable(do_add))

    # helper: send currently edited request (from reqEditor) to Burp Repeater
    def _send_editor_request_to_repeater(self):
        try:
            # obtain message from request editor (if present)
            msg = None
            try:
                if getattr(self, 'reqEditor', None):
                    msg = self.reqEditor.getMessage()
                else:
                    # fallback: text from edit pane
                    txt = self.request_pane_edit.getText() if getattr(self, 'request_pane_edit', None) else None
                    msg = self._helpers.stringToBytes(txt) if txt is not None else None
            except:
                msg = None

            if msg is None:
                self.stdout.println("[UI] No request in editor to send to Repeater")
                return

            host = None; port = None; useHttps = False
            try:
                analyzed = self._helpers.analyzeRequest(msg)
                url = analyzed.getUrl()
                host = url.getHost(); port = url.getPort(); proto = url.getProtocol()
                useHttps = (proto == 'https')
                if port == -1:
                    port = 443 if useHttps else 80
            except:
                # fallback: parse Host header
                try:
                    s = self._helpers.bytesToString(msg)
                    for line in s.splitlines():
                        if line.lower().startswith("host:"):
                            parts = line.split(":",1)[1].strip()
                            if ":" in parts:
                                host, port = parts.split(":",1)
                                port = int(port)
                            else:
                                host = parts; port = 443 if useHttps else 80
                            break
                except:
                    pass

            if not host:
                self.stdout.println("[UI] Could not determine host/port for Repeater send")
                return

            sent = False
            last_exc = None
            try:
                svc = self._helpers.buildHttpService(host, int(port), bool(useHttps))
                self._callbacks.sendToRepeater(svc, msg)
                sent = True
            except Exception as e:
                last_exc = e
                # try other overloads
                try:
                    self._callbacks.sendToRepeater(host, int(port), bool(useHttps), msg, None)
                    sent = True
                except Exception as e2:
                    last_exc = e2
                    try:
                        self._callbacks.sendToRepeater(host, int(port), bool(useHttps), msg)
                        sent = True
                    except Exception as e3:
                        last_exc = e3

            if sent:
                self.stdout.println("[UI] Sent editor request to Repeater: %s:%s" % (host, port))
            else:
                self.stderr.println("[UI] Send to Repeater failed: %s" % str(last_exc))
        except Exception:
            try:
                self.stderr.println("[UI] _send_editor_request_to_repeater exception")
                self.stderr.println(traceback.format_exc())
            except:
                pass

class Tab(ITab):
    def __init__(self, title, component):
        self._title = title
        self._component = component
    def getTabCaption(self):
        return self._title
    def getUiComponent(self):
        return self._component

class ProxyListener(IHttpListener):
    def __init__(self, ext):
        self.ext = ext

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            # debug: log incoming callbacks so we can inspect behaviour
            try:
                self.ext.stdout.println("[ProxyListener] called: tool=%s isRequest=%s msgType=%s" %
                    (str(toolFlag), str(messageIsRequest), str(type(messageInfo))))
            except:
                pass

            # only care about proxy tool responses (we want a response to inspect status)
            if (not messageIsRequest) and toolFlag == self.ext._callbacks.TOOL_PROXY:
                try:
                    self.ext.stdout.println("[ProxyListener] proxy response detected")
                except:
                    pass
                # auto-enqueue removed — keep lightweight logging for proxy responses
                try:
                    resp = messageInfo.getResponse()
                    if resp is None:
                        return
                    code = self.ext._helpers.analyzeResponse(resp).getStatusCode()
                    url = self.ext._helpers.analyzeRequest(messageInfo).getUrl()
                    self.ext.stdout.println("[ProxyListener] url=%s status=%s (auto-enqueue disabled)" %
                                            (url.toString(), str(code)))
                except Exception:
                    self.ext.stderr.println("[ProxyListener] inspect exception")
                    self.ext.stderr.println(traceback.format_exc())
        except Exception:
            try:
                self.ext.stderr.println("[ProxyListener] outer exception")
                self.ext.stderr.println(traceback.format_exc())
            except:
                pass

class ContextMenuFactory(IContextMenuFactory):
    def __init__(self, ext):
        self.ext = ext
    def createMenuItems(self, invocation):
        try:
            msgs = invocation.getSelectedMessages()
            self.ext.stdout.println("[ContextMenu] createMenuItems called, selected=%s" % str(bool(msgs)))
            if not msgs:
                return None
            # create a menu item that enqueues the currently selected messages when clicked
            item = swing.JMenuItem('Send to 403 Bypasser', actionPerformed=lambda e, inv=invocation: self.on_click(inv.getSelectedMessages()))
            return [item]
        except Exception:
            self.ext.stderr.println("[ContextMenu] createMenuItems exception")
            self.ext.stderr.println(traceback.format_exc())
            return None
    def on_click(self, msgs):
        try:
            self.ext.stdout.println("[ContextMenu] clicked, count=%s" % str(len(msgs) if msgs else 0))
            for m in msgs:
                try:
                    self.ext.enqueue_request(m, source='Proxy-Context')
                    self.ext.stdout.println('[ContextMenu] enqueued (Proxy-Context): %s' % self.ext._helpers.analyzeRequest(m).getUrl())
                except Exception:
                    self.ext.stderr.println("[ContextMenu] enqueue exception")
                    self.ext.stderr.println(traceback.format_exc())
        except Exception:
            try:
                self.ext.stderr.println("[ContextMenuFactory] outer exception")
                self.ext.stderr.println(traceback.format_exc())
            except:
                pass

# Add a small Job wrapper
class Job:
    def __init__(self, req, source='UI'):
        self.req = req
        self.source = source

# End of extension
# Notes:
# - This is a standalone UI that enqueues requests manually (select a request in Burp and click "Enqueue Selected Request").
# - It respects scope (callbacks.isInScope) and a simple rate limit. You can enhance it to auto-enqueue certain traffic,
#   persist results, export CSV, or add more payloads.
# - Do NOT run against targets you're not authorized to test. Always follow rules of engagement.
