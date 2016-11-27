import webapp2
import jinja2
import os
from google.appengine.ext import db
import re
import logging
import hashlib

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape=True)

secret = 'vjdnfjskygr8274592yuehdjbfab237y89123hdwjndka'

def render_str(template,**params):
	t = jinja_env.get_template(template)
	return t.render(params)

def valid_username(user):
    name = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return user and name.match(user)

def valid_password(password):
    passw = re.compile(r"^.{3,20}$")
    return password and passw.match(password)

def valid_email(email):
    e = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return email and e.match(email)




    

class Handler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.out.write(*a,**kw)

    def render(self,template,**kw):
        self.response.out.write(render_str(template,**kw))

    def hash_str(self,some_text):
        hash_text = hashlib.sha256(str(some_text)+secret).hexdigest()
        return hash_text

    def verify_cookie(self,val):
        logging.info(val)
        val_a = val.split('|')
        if self.hash_str(val_a[0]) == val_a[1]:
            return val_a[0]

    def check_id_cookie(self):
        cookie = self.request.cookies.get('user_id')
        if cookie:
            verification = self.verify_cookie(cookie)
            if verification:
                logging.info("cookie verified")
                u = User.get_by_id(int(verification),parent = None)
                logging.info(u.username)
                return u

    def set_secure_cookie(self,user_id):
        hash_id = self.hash_str(user_id)
        self.response.headers.add_header('Set-Cookie','%s|%s'%(user_id,hash_id))

    


class MainHandler(Handler):
    def get(self):
    	enteries = db.GqlQuery('select * from codeobject order by created desc')
        self.render('main.html',enteries = enteries)
        mgw = self.request.cookies.get('MGW','false')



class Signup(Handler):
    def get(self):
        cookie = self.request.cookies.get('user_id')
        if cookie:
            if self.verify_cookie(cookie):
                self.redirect('/welcome')
            else:
                self.render('signup.html')
        else:
            self.render('signup.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        params = {'username':username}
        valid_form = True

        if not valid_username(username):
            params['error_username'] = 'Username is too short'
            valid_form = False
        if not valid_password(password):
            params['error_password'] = 'Password is too short'
            valid_form = False
        if password != verify:
            params['error_verify'] = 'Passwords do not match'
            valid_form = False
        if email:
            if not valid_email(email):
                params['error_email'] = 'Email is missing'
                valid_form = False

        if valid_form:
            hash_password = self.hash_str(password)
            new_user = User(username = username, password = hash_password, email = email)
            new_user_key = new_user.put()
            user_id = new_user_key.id()
            id_hash = self.hash_str(user_id)
            self.response.headers.add_header('Set-Cookie',str('user_id=%s|%s; PATH=/'%(user_id,id_hash)))
            self.redirect('/welcome')
        else:
            self.render('signup.html',**params)



# class Login(Handler):
#     def get(self):
        




class Welcome(Handler):
    def get(self):
        u = self.check_id_cookie()
        if u:
            self.render('welcome.html',user = u.username)
        else:
            self.redirect('/signup')



    
class NewPost(Handler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        title = self.request.get('subject')
        code = self.request.get('content')
        if title and code:
            new_entery = codeobject(title = title, code = code)
            key = new_entery.put()
            entry_id = '/' + str(key.id())
            logging.info(entry_id)
            self.redirect(entry_id)
        else:
            logging.info('Error with post')
            self.render('newpost.html',error_message = 'Both a title and code is required!')



class Entery(Handler):
    def get(self,post_id):
        entery = codeobject.get_by_id(int(post_id))

        self.render('entery.html',entery = entery)



class codeobject(db.Model):
    title = db.StringProperty(required = True)
    code = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newpost',NewPost),
    ('/([0-9]+)',Entery),
    ('/signup',Signup),
    ('/welcome',Welcome)
], debug=True)








