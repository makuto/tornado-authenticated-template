#!/usr/bin/env python3

import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.httpclient
import tornado.gen

import os
import random

# Require a username and password in order to use the web interface. See ReadMe.org for details.
#enable_authentication = False
enable_authentication = True

# Allow anyone to create an account even after the first account has been created
# This is a security vulnerability that should be considered before being enabled.
# Do you want anyone to be able to use the service provided by your server?
enable_subsequent_account_creation = False
# enable_subsequent_account_creation = True

# If "next" isn't specified from login, redirect here after login instead
landingPage = "/"

if enable_authentication:
    import PasswordManager

# List of valid user ids (used to compare user cookie)
authenticated_users = []

# See https://github.com/tornadoweb/tornado/blob/stable/demos/blog/blog.py
# https://www.tornadoweb.org/en/stable/guide/security.html

def login_get_current_user(handler):
    if enable_authentication:
        cookie = handler.get_secure_cookie("user")
        if cookie in authenticated_users:
            return cookie
        else:
            print("Bad/expired cookie received")
            return None
    else:
        return "authentication_disabled"

class AuthHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return login_get_current_user(self)

class LoginNewAccountHandler(AuthHandler):
    def get(self):
        if not enable_subsequent_account_creation:
            self.redirect("/login")
        else:
            # New password setup
            self.render("templates/LoginCreate.html",
                        next=self.get_argument("next", landingPage),
                        xsrf_form_html=self.xsrf_form_html())
    
class LoginHandler(AuthHandler):
    def get(self):
        if not enable_authentication:
            self.redirect("/")
        else:
            if PasswordManager.havePasswordsBeenSet():
                self.render("templates/Login.html",
                            next=self.get_argument("next", landingPage),
                            xsrf_form_html=self.xsrf_form_html(),
                            create_accounts_html = ("" if not enable_subsequent_account_creation
                                                    else '<p>Go <a href="/createNewAccount">here</a> to create an account.</p>'))
            else:
                # New password setup
                self.render("templates/LoginCreate.html",
                            next=self.get_argument("next", landingPage),
                            xsrf_form_html=self.xsrf_form_html())

    def post(self):
        global authenticated_users
        # Test password
        print("Attempting to authorize user {}...".format(self.get_argument("name")))
        if (enable_authentication
            and PasswordManager.verify(self.get_argument("name"), self.get_argument("password"))):
            # Generate new authenticated user session
            randomGenerator = random.SystemRandom()
            cookieSecret = str(randomGenerator.getrandbits(128))
            authenticated_user = self.get_argument("name") + "_" + cookieSecret
            authenticated_user = authenticated_user.encode()
            authenticated_users.append(authenticated_user)
            
            # Set the cookie on the user's side
            self.set_secure_cookie("user", authenticated_user)
            
            print("Authenticated user {}".format(self.get_argument("name")))
            
            # Let them in
            self.redirect(self.get_argument("next", landingPage))
        else:
            print("Refused user {} (password doesn't match any in database)"
                  .format(self.get_argument("name")))
            self.redirect("/login")

class LogoutHandler(AuthHandler):
    @tornado.web.authenticated
    def get(self):
        global authenticated_users
        
        if enable_authentication:
            print("User {} logging out".format(self.current_user))
            if self.current_user in authenticated_users:
                authenticated_users.remove(self.current_user)
                self.redirect("/login")
        else:
            self.redirect("/")

class CreateAccountHandler(AuthHandler):
    def get(self):
        pass

    def post(self):
        if not enable_authentication:
            self.redirect("/")
        else:
            print("Attempting to set password")
            if not enable_subsequent_account_creation and PasswordManager.havePasswordsBeenSet():
                print("Rejected: Accounts cannot be created via the server if one already has been made.")
            elif self.get_argument("password") != self.get_argument("password_verify"):
                print("Rejected: password doesn't match verify field!")
            else:
                result = PasswordManager.createAccount(self.get_argument("name"),
                                                       self.get_argument("password"))
                if not result[0]:
                    print("Failed: {}".format(result[1]))
                print("Success: {}".format(result[1]))

            self.redirect("/login")

class AuthedStaticHandler(tornado.web.StaticFileHandler):
    def get_current_user(self):
        return login_get_current_user(self)
    
    @tornado.web.authenticated
    def prepare(self):
        pass

class HomeHandler(AuthHandler):
    @tornado.web.authenticated
    def get(self):
        # Replace with your desired behavior, e.g. 
        # self.render('webInterface/index.html')
        self.write('You are logged in!')

class ExampleWebSocket(tornado.websocket.WebSocketHandler):
    connections = set()

    def open(self):
        global userSessionData
        currentUser = login_get_current_user(self)
        if not currentUser:
            # Failed authorization
            return None
        
        self.connections.add(self)
        
    def on_message(self, message):
        currentUser = login_get_current_user(self)
        if not currentUser:
            # Failed authorization
            return None
        
    def on_close(self):
        self.connections.remove(self)

#
# Startup
#

def make_app():
    # Each time the server starts up, invalidate all cookies
    randomGenerator = random.SystemRandom()
    cookieSecret = str(randomGenerator.getrandbits(128))
    
    return tornado.web.Application([
        (r'/', HomeHandler),

        # Login
        (r'/login', LoginHandler),
        (r'/logout', LogoutHandler),
        (r'/createNewAccount', LoginNewAccountHandler),
        (r'/finishCreateAccount', CreateAccountHandler),
        
        # (r'/ExampleWebSocket', ExampleWebSocket),

        # Static files
        # (r'/webInterface/(.*)', AuthedStaticHandler, {'path' : 'webInterface'}),

        # Files served regardless of whether the user is authenticated. Only login page resources
        # should be in this folder, because anyone can see them
        (r'/webInterfaceNoAuth/(.*)', tornado.web.StaticFileHandler, {'path' : 'webInterfaceNoAuth'}),
    ],
                                   xsrf_cookies=True,
                                   cookie_secret=cookieSecret,
                                   login_url="/login")

if __name__ == '__main__':
    port = 8888
    print('\nStarting Authenticated Server on port {}...'.format(port))
    app = make_app()

    # Generating a self-signing certificate:
    # openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout certificates/server_jupyter_based.crt.key -out certificates/server_jupyter_based.crt.pem
    # (from https://jupyter-notebook.readthedocs.io/en/latest/public_server.html)
    # I then had to tell Firefox to trust this certificate even though it is self-signing (because
    # I want a free certificate for this non-serious project)
    useSSL = True
    if useSSL:
        if os.path.exists("certificates/server.crt.pem"):
            app.listen(port, ssl_options={"certfile":"certificates/server.crt.pem",
                                          "keyfile":"certificates/server.crt.key"})
        else:
            print('\n\tERROR: Certificates non-existent! Run ./Generate_Certificates.sh to create them')
    else:
        # Show the warning only if SSL is not enabled
        print('\n\tWARNING: Do NOT run this server on the internet (e.g. port-forwarded)'
              ' nor when\n\t connected to an insecure LAN! It is not protected against malicious use.\n')
        app.listen(port)
        
    ioLoop = tornado.ioloop.IOLoop.current()
    ioLoop.start()
