#
# Copyright 2020 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import http.server
import json

class Server(http.server.BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
    def do_HEAD(self):
        self._set_headers()
    def do_GET(self):
        self._set_headers()
        self.wfile.write((json.dumps({'response': 'message arrived !', 'received': 'ok'})).encode())
    def do_POST(self):
        content_type, pdict = cgi.parse_header(self.headers.getheader('content-type'))
        if content_type != 'application/json':
            self.send_response(400)
            self.end_headers()
            return
        length = int(self.headers.getheader('content-length'))
        message = json.loads(self.rfile.read(length))
        message['received'] = 'ok'
        mesaage["message"]= "A post requst was recieved !"
        self._set_headers()
        self.wfile.write(json.dumps(message))

def run(server_class=http.server.HTTPServer, handler_class=Server, port=8080):
    server_address = ('0.0.0.0', port)
    httpd = server_class(server_address, handler_class)
    print ('Starting httpd on port %d...' % port)
    httpd.serve_forever()
if __name__ == "__main__":
    from sys import argv
    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
