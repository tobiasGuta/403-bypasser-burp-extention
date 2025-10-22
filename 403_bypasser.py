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
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Dimension, Font, Color
from java.awt.event import ActionListener
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Dimension, Font, Color
from java.awt.event import ActionListener
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Dimension, Font, Color
from java.awt.event import ActionListener
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
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
                try:
                    time.sleep(1.0 / max(0.1, float(self.ext.rate_limit)))
                except Exception:
                    # fallback sleep so loop doesn't spin on unexpected rate_limit issues
                    time.sleep(0.2)

                # Auto-stop behaviour:
                # If there are no queued jobs left after finishing the current one,
                # stop the worker automatically and update the UI on the EDT.
                try:
                    if not self.stop_event.is_set():
                        # use ext.jobs (may be missing) — treat missing/empty as empty queue
                        queued = getattr(self.ext, 'jobs', None)
                        if not queued:
                            self.ext.stdout.println("[BypassWorker] queue empty -> auto-stopping")
                            try:
                                self.stop_event.set()
                            except:
                                pass
                            def do_auto_stop():
                                try:
                                    # clear worker reference and update buttons safely on EDT
                                    try:
                                        self.ext.worker = None
                                    except:
                                        pass
                                    try:
                                        self.ext.start_btn.setEnabled(True)
                                    except:
                                        pass
                                    try:
                                        self.ext.stop_btn.setEnabled(False)
                                    except:
                                        pass
                                except:
                                    pass
                            SwingUtilities.invokeLater(FuncRunnable(do_auto_stop))
                            break
                except Exception:
                    # never let auto-stop checks crash the worker loop
                    pass

            self.ext.stdout.println("[BypassWorker] stopped")
        except Exception as e:
            self.ext.stderr.println("[BypassWorker] exception: %s" % str(e))
            self.ext.stderr.println(traceback.format_exc())

    def try_bypass(self, baseRequestResponse):
        """
        Enhanced 403 bypass attempts with path, header, method and encoding tricks.

        Quick manual test:
         - In Burp select a request that returned 403 -> right-click -> Send to 403 Bypasser.
         - Ensure toggles (Path payloads, Header payloads, Method & Encoding) are checked.
         - Start the worker and observe results in the UI table.

        The function is conservative: only reports 2xx/3xx responses and applies heuristics
        to classify confidence (High/Medium/Low). It checks self.ext.stop_event frequently.
        """
        try:
            import re
            helpers = self.ext._helpers
            analyzed = helpers.analyzeRequest(baseRequestResponse)
            url = analyzed.getUrl()
            path = url.getPath() or "/"
            if path == "":
                path = "/"

            # only attempt when original response was 403
            orig_response = baseRequestResponse.getResponse()
            if orig_response is None:
                return
            orig_code = helpers.analyzeResponse(orig_response).getStatusCode()
            if orig_code != 403:
                return

            # baseline body (only body portion) and normalized form
            try:
                resp_info = helpers.analyzeResponse(orig_response)
                body_offset = resp_info.getBodyOffset()
                baseline_body_bytes = orig_response[body_offset:]
                baseline_body = helpers.bytesToString(baseline_body_bytes) if baseline_body_bytes else ""
            except Exception:
                baseline_body = ""
                baseline_body_bytes = ""
            baseline_len = len(orig_response)

            def normalize_body(s):
                try:
                    s = (s or "").lower()
                    # collapse whitespace
                    s = re.sub(r'\s+', ' ', s)
                    # strip long numeric sequences (timestamps/ids) to avoid FP
                    s = re.sub(r'\d{5,}', '', s)
                    return s.strip()
                except:
                    return s or ""

            baseline_norm = normalize_body(baseline_body)

            # prepare canonical pieces
            orig_headers = list(analyzed.getHeaders())
            body_bytes = baseRequestResponse.getRequest()[analyzed.getBodyOffset():]
            clean_path = path.rstrip('/') if path != '/' else '/'
            last_segment = clean_path.split('/')[-1] if clean_path != '/' else ''

            # payload lists (as requested)
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
                    last_segment + "/.randomstring",
                    last_segment + ";jsessionid=FAKE",
                    "%2e%2e/" + last_segment
                ]
            # include query/host tweaks as simple appended variants (avoid duplication)
            query_payloads = ["?", "?_=0", "?debug=1", "?%20="]

            header_payloads = [
                ("X-Original-URL", path + "4nyth1ng"),
                ("X-Rewrite-URL", path),
                ("Referer", "/" + last_segment if last_segment else "/"),
                ("X-Custom-IP-Authorization", "127.0.0.1"),
                ("X-Originating-IP", "127.0.0.1"),
                ("X-Forwarded-For", "127.0.0.1"),
                ("X-Client-IP", "127.0.0.1"),
                ("X-Host", "127.0.0.1"),
                ("X-Forwarded-Host", url.getHost()),
                ("X-Original-Host", url.getHost()),
                ("X-HTTP-Method-Override", "GET"),
                ("X-Original-Method", "GET"),
                ("Authorization", "Bearer garbage"),
                ("User-Agent", "Mozilla/5.0 (compatible; bypasser)"),
                ("X-Requested-With", "XMLHttpRequest")
            ]

            method_variants = ["GET", "HEAD", "POST", "OPTIONS", "PUT", "PATCH"]

            # encoding/content-length tricks (safe minimal forms)
            encodings = [
                ("none", None, body_bytes),
                ("content-length-0", ("Content-Length", "0"), helpers.stringToBytes("") ),
                ("chunked", ("Transfer-Encoding", "chunked"), helpers.stringToBytes("0\r\n\r\n")),
                ("chunked+cl0", ("both", "both"), helpers.stringToBytes("0\r\n\r\n"))
            ]

            deny_keywords = ["forbidden", "access denied", "you don't have permission", "not authorized", "error 403", "403 forbidden"]

            results = []

            # Helper: evaluate a candidate response and append to results if status in 2xx/3xx
            def evaluate_candidate(kind, payload_desc, rr):
                try:
                    if self.ext.stop_event.is_set():
                        return
                    resp = rr.getResponse()
                    if resp is None:
                        return
                    code = helpers.analyzeResponse(resp).getStatusCode()
                    # report any status different from the original (not only 2xx/3xx)
                    if code != orig_code:
                        results.append((kind, payload_desc, code, rr))
                except Exception:
                    pass

            # PATH payloads (only when enabled)
            try:
                if getattr(self.ext, 'toggle_path', None) and self.ext.toggle_path.isSelected():
                    # use original request line to build new paths
                    for p in path_payloads + query_payloads:
                        if self.ext.stop_event.is_set():
                            return
                        new_headers = list(orig_headers)
                        first = new_headers[0]
                        try:
                            method, req_path, proto = first.split(' ', 2)
                        except ValueError:
                            self.ext.stderr.println("[try_bypass] malformed request line, skipping path payload")
                            break

                        # If payload looks like a query tweak, append to the current req_path
                        if p and p.startswith('?'):
                            new_path = req_path + p
                        else:
                            # parent path assembly (avoid duplicate slashes)
                            parent = '/'.join(req_path.rstrip('/').split('/')[:-1])
                            if parent == '':
                                parent = '/'
                            if parent == '/':
                                new_path = '/' + p.lstrip('/')
                            else:
                                new_path = parent.rstrip('/') + '/' + p.lstrip('/')

                        new_headers[0] = "%s %s %s" % (method, new_path, proto)
                        new_req = helpers.buildHttpMessage(new_headers, body_bytes)
                        rr = self.ext._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_req)
                        evaluate_candidate("path", new_path, rr)
            except Exception:
                self.ext.stderr.println("[try_bypass] path payloads exception")
                self.ext.stderr.println(traceback.format_exc())

            # HEADER payloads (single header at a time to limit explosion)
            try:
                if getattr(self.ext, 'toggle_headers', None) and self.ext.toggle_headers.isSelected():
                    for hname, hval in header_payloads:
                        if self.ext.stop_event.is_set():
                            return
                        try:
                            # remove existing header with same name (case-insensitive)
                            new_headers = [h for h in orig_headers if not h.lower().startswith(hname.lower() + ":")]
                            new_headers.append("%s: %s" % (hname, hval))
                            new_req = helpers.buildHttpMessage(new_headers, body_bytes)
                            rr = self.ext._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_req)
                            evaluate_candidate("header", "%s: %s" % (hname, hval), rr)
                        except Exception:
                            pass
            except Exception:
                self.ext.stderr.println("[try_bypass] header payloads exception")
                self.ext.stderr.println(traceback.format_exc())

            # METHOD + ENCODING tricks (single-pass, do not combine with header/path payloads to avoid explosion)
            try:
                if getattr(self.ext, 'toggle_methods_encoding', None) and self.ext.toggle_methods_encoding.isSelected():
                    first = orig_headers[0]
                    try:
                        _orig_method, req_path, proto = first.split(' ', 2)
                    except ValueError:
                        req_path = path
                        proto = "HTTP/1.1"

                    for m in method_variants:
                        if self.ext.stop_event.is_set():
                            return
                        for enc in encodings:
                            if self.ext.stop_event.is_set():
                                return
                            enc_name = enc[0]
                            # build headers: replace request line, remove existing TE/Content-Length
                            new_headers = [h for h in orig_headers if not (h.lower().startswith("transfer-encoding:") or h.lower().startswith("content-length:"))]
                            new_headers[0] = "%s %s %s" % (m, req_path, proto)

                            # apply encoding variant
                            body_for_req = body_bytes
                            if enc_name == "content-length-0":
                                new_headers.append("Content-Length: 0")
                                body_for_req = helpers.stringToBytes("")
                            elif enc_name == "chunked":
                                new_headers.append("Transfer-Encoding: chunked")
                                body_for_req = helpers.stringToBytes("0\r\n\r\n")
                            elif enc_name == "chunked+cl0":
                                new_headers.append("Transfer-Encoding: chunked")
                                new_headers.append("Content-Length: 0")
                                body_for_req = helpers.stringToBytes("0\r\n\r\n")

                            new_req = helpers.buildHttpMessage(new_headers, body_for_req)
                            rr = self.ext._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_req)
                            evaluate_candidate("method", "%s + %s" % (m, enc_name), rr)
            except Exception:
                self.ext.stderr.println("[try_bypass] method/encoding exception")
                self.ext.stderr.println(traceback.format_exc())

            # Now score/filter results with smarter heuristics and add to UI
            try:
                for kind, payload, code, rr in results:
                    if self.ext.stop_event.is_set():
                        return
                    try:
                        resp = rr.getResponse()
                        resp_info = helpers.analyzeResponse(resp)
                        body_offset = resp_info.getBodyOffset()
                        resp_body_bytes = resp[body_offset:] if resp is not None else ""
                        resp_body = helpers.bytesToString(resp_body_bytes) if resp_body_bytes else ""
                        resp_norm = normalize_body(resp_body)
                        resp_len = len(resp)
    
                        # check deny keywords
                        deny_found = False
                        lower = resp_norm.lower() if resp_norm else ""
                        for k in deny_keywords:
                            if k in lower:
                                deny_found = True
                                break
    
                        confidence = "Low (possible FP)"
                        # heuristics: report when status differs from original 403
                        if code != orig_code:
                            if resp_norm != baseline_norm and not deny_found:
                                confidence = "High"
                            elif resp_norm != baseline_norm and deny_found:
                                confidence = "Medium"
                            elif resp_len != baseline_len and resp_norm == baseline_norm:
                                confidence = "Medium"
                            else:
                                confidence = "Low (possible FP)"
                            try:
                                self.ext.add_result(url.toString(), kind, payload, code, confidence, rr)
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception:
                self.ext.stderr.println("[try_bypass] scoring exception")
                self.ext.stderr.println(traceback.format_exc())

        except Exception as e:
            self.ext.stderr.println("[try_bypass] exception: %s" % str(e))
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

         # Add toggles for payload categories (default: checked)
         self.toggle_path = swing.JCheckBox('Path payloads', selected=True)
         controls.add(self.toggle_path, gbc)
         gbc.gridx += 1
         self.toggle_headers = swing.JCheckBox('Header payloads', selected=True)
         controls.add(self.toggle_headers, gbc)
         gbc.gridx += 1
         self.toggle_methods_encoding = swing.JCheckBox('Method & Encoding', selected=True)
         controls.add(self.toggle_methods_encoding, gbc)
         gbc.gridx += 1

         # removed "Auto-enqueue" and "Enqueue Selected Request" UI elements per request;
         # keep a small spacer so layout remains stable
         controls.add(swing.JLabel(""), gbc)
         gbc.gridx += 1
         # Clear log / history button
         self.clear_btn = swing.JButton('Clear Log', actionPerformed=self.clear_clicked)
         controls.add(self.clear_btn, gbc)
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
         # colorize HTTP column (index 3)
         try:
            self.result_table.getColumnModel().getColumn(3).setCellRenderer(StatusCellRenderer())
         except:
            pass
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
 
     def clear_clicked(self, event):
         """
         Clear UI history: queued jobs, results table, result_items, reset queue label,
         and also clear request/response editors (if present).
         Runs on EDT.
         """
         def do_clear():
             try:
                 # clear backend queues
                 try:
                     self.jobs = []
                 except:
                     pass
                 try:
                     self.result_items = []
                 except:
                     pass

                 # clear queue table model
                 try:
                     while self.queue_model.getRowCount() > 0:
                         self.queue_model.removeRow(0)
                 except:
                     try:
                         self.queue_model.setRowCount(0)
                     except:
                         pass

                 # clear results table model
                 try:
                     while self.table_model.getRowCount() > 0:
                         self.table_model.removeRow(0)
                 except:
                     try:
                         self.table_model.setRowCount(0)
                     except:
                         pass

                 # prepare empty payload for editors (use helpers if available)
                 try:
                     empty_bytes = self._helpers.stringToBytes("") if getattr(self, '_helpers', None) else ""
                 except:
                     empty_bytes = ""

                 # clear request editor (Burp message editor or fallback component)
                 try:
                     if getattr(self, 'reqEditor', None):
                         try:
                             # set an explicit empty message (some editors ignore None)
                             self.reqEditor.setMessage(empty_bytes, True)
                         except:
                             # fallback to clearing the editor component text
                             try:
                                 comp = self.reqEditor.getComponent()
                                 if hasattr(comp, 'setText'):
                                     comp.setText("")
                             except:
                                 pass
                     else:
                         comp = getattr(self, 'request_pane', None)
                         if comp is not None:
                             try:
                                 if hasattr(comp, 'setMessage'):
                                     comp.setMessage(empty_bytes, True)
                                 elif hasattr(comp, 'setText'):
                                     comp.setText("")
                             except:
                                 pass
                         # also clear any edit-pane variant
                         try:
                             if getattr(self, 'request_pane_edit', None) and hasattr(self.request_pane_edit, 'setText'):
                                 self.request_pane_edit.setText("")
                         except:
                             pass
                 except:
                     pass

                 # clear response editor (Burp message editor or fallback component)
                 try:
                     if getattr(self, 'respEditor', None):
                         try:
                             self.respEditor.setMessage(empty_bytes, False)
                         except:
                             try:
                                 comp = self.respEditor.getComponent()
                                 if hasattr(comp, 'setText'):
                                     comp.setText("")
                             except:
                                 pass
                     else:
                         comp = getattr(self, 'response_pane', None)
                         if comp is not None:
                             try:
                                 if hasattr(comp, 'setMessage'):
                                     comp.setMessage(empty_bytes, False)
                                 elif hasattr(comp, 'setText'):
                                     comp.setText("")
                             except:
                                 pass
                 except:
                     pass

                 # reset queue label
                 try:
                     self.queue_label.setText("Queued URL: <none>")
                 except:
                     pass

                 self.stdout.println("[UI] Cleared log/history (editors cleared)")
             except Exception:
                 try:
                     self.stderr.println("[UI] clear_clicked exception")
                     self.stderr.println(traceback.format_exc())
                 except:
                     pass

         # enqueue the UI update on the Swing EDT
         SwingUtilities.invokeLater(FuncRunnable(do_clear))
 
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

class StatusCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        # get default component (handles font/selection)
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        try:
            comp.setOpaque(True)
        except:
            pass

        # parse numeric status if possible
        try:
            code = int(str(value).strip())
        except:
            code = None

        # preserve selection appearance
        if isSelected:
            comp.setBackground(table.getSelectionBackground())
            comp.setForeground(table.getSelectionForeground())
            return comp

        # color mapping (light backgrounds for readability)
        if code is None:
            comp.setBackground(Color(250,250,250))
            comp.setForeground(Color.black)
        elif 200 <= code < 300:
            comp.setBackground(Color(198,239,206))   # light green
            comp.setForeground(Color.black)
        elif 300 <= code < 400:
            comp.setBackground(Color(255,243,205))   # light yellow
            comp.setForeground(Color.black)
        elif 400 <= code < 500:
            comp.setBackground(Color(255,199,206))   # light red/pink
            comp.setForeground(Color.black)
        elif 500 <= code < 600:
            comp.setBackground(Color(224,224,224))   # grey
            comp.setForeground(Color.black)
        else:
            comp.setBackground(Color.white)
            comp.setForeground(Color.black)

        return comp
