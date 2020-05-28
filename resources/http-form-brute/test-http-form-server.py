#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer

#Global settings to allow you to configure test password and user

# Test username is the 10th username in the metasploit unix_users list
test_username = 'auditor'
# Test password is the 1000th password in fasttrack.txt
test_password = 'starwars'
login_path = '/login.php'

class TestSrv(BaseHTTPRequestHandler):
    def _respond(self, resp):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        try:
            self.wfile.write(resp.encode())
        except Exception as e:
            print("Couldn't respond :\n{}".format(e))

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode()
        #Debug output, can be uncommented if you like
        #print("POST request,\nPath: {}\nHeaders : \n{}Body : \n{}\n".format(
        #        str(self.path), str(self.headers), post_data))
        
        #Extract login data and respond accordingly

        #First, make sure path is right
        if self.path != login_path:
            print("Got Bad request, login path incorrect : {}\nTry {}".format(self.path, login_path))
            self._respond("Bad request, login path incorrect, try {login_path}")
            return

        #get username and pass and respond accordingly
        user = post_data[5:int(post_data.index('&'))]
        passwd = post_data[int(post_data.index('&'))+6:]
        resp="Login status : "
        if (test_username not in post_data):
            resp += 'Bad username'
        else:
            resp += 'Login successful!' if test_password in post_data else 'Bad password'
        if 'Login successful' not in resp : resp += ' - Login failed.'
        print("Login guess | User : {} | Password : {} | Login response : {} ".format(user, passwd, resp))
        self._respond(resp)

def main(server_class=HTTPServer, handler_class=TestSrv, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print('Stopping httpd...\n')

if __name__ == '__main__':
    from sys import argv
    port = int(argv[1]) if len(argv) >= 2 else 8080
    main(port=port)
