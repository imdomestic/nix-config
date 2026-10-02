"""One-shot diagnostic upload from the VM, bound only to its NAT bridge."""
import http.server
import json
import pathlib

destination = pathlib.Path('/var/tmp/268v-vfio-probe/guest.json')


class Receiver(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        size = int(self.headers.get('Content-Length', '0'))
        if self.path != '/report' or not 0 < size <= 2 * 1024 * 1024:
            self.send_error(400)
            return
        try:
            report = json.loads(self.rfile.read(size))
        except (ValueError, UnicodeError):
            self.send_error(400)
            return
        destination.write_text(json.dumps(report, ensure_ascii=False, indent=2))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')


http.server.HTTPServer(('192.168.178.1', 8765), Receiver).serve_forever()
