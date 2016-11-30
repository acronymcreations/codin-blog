import webapp2
import jinja2
import os
from google.appengine.ext import db
import re
import logging
import hashlib
import time

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
                return u

    def set_secure_cookie(self,user_id):
        hash_id = self.hash_str(user_id)
        self.response.headers.add_header('Set-Cookie','user_id=%s|%s;PATH=/'%(user_id,hash_id))

class MainHandler(Handler):
    def get(self):
        u = self.check_id_cookie()
    	enteries = db.GqlQuery('select * from PostObject order by created desc')
        logging.info(enteries[0].likes)
        logging.info(len(enteries[0].likes))
        self.render('main.html',enteries = enteries, user = u)

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

        already_exists = db.GqlQuery("select * from User where username = '%s'"%username).get()
        if already_exists:
            params['error_username'] = 'Username is already taken'
            valid_form = False
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
            new_user = User(username = username, password = hash_password, email = email,likes = [])
            new_user_key = new_user.put()
            user_id = new_user_key.id()
            id_hash = self.hash_str(user_id)
            self.set_secure_cookie(user_id)
            self.redirect('/welcome')
        else:
            self.render('signup.html',**params)

class Login(Handler):
    def get(self):
        user_id = self.check_id_cookie()
        if user_id:
            self.redirect('/welcome')
        self.render('/login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = db.GqlQuery("select * from User where username = '%s'"%username).get()
        if u:
            if self.hash_str(password) == u.password:
                logging.info('user is authenticated')
                self.set_secure_cookie(u.key().id())
                self.redirect('/welcome')
            else:
                self.render('login.html',username = username,error = 'Invalid username and/or password')

        else:
            self.render('login.html',username = username,error = 'Invalid username and/or password')
        
class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie','user_id=;PATH=/')
        self.redirect('/login')

class Welcome(Handler):
    def get(self):
        u = self.check_id_cookie()
        if u:
            posts = db.GqlQuery("select * from PostObject where posted_by = '%s' order by created desc"%u.username).fetch(limit=None)
            self.render('welcome.html',user = u,posts = posts)
        else:
            self.redirect('/login')

class PostsBy(Handler):
    def get(self,poster):
        user = self.check_id_cookie()
        posts = db.GqlQuery("select * from PostObject where posted_by = '%s' order by created desc"%poster).fetch(limit=None)
        self.render('postsby.html',posts = posts,user = user,poster = poster)
   
class NewPost(Handler):
    def get(self):
        u = self.check_id_cookie()
        if u:
            self.render('newpost.html',user = u)
        else:
            self.redirect('/login')

    def post(self):
        u = self.check_id_cookie();
        if not u:
            redirect('/login')
        title = self.request.get('subject')
        summary = self.request.get('summary')
        code = self.request.get('content')
        
        if title and code and summary:
            new_entery = PostObject(title = title,summary = summary,code = code,posted_by = u.username)
            key = new_entery.put()
            entry_id = '/' + str(key.id())
            logging.info(entry_id)
            self.redirect(entry_id)
        else:
            self.render('newpost.html',error_message = 'All fields are required!',title = title,summary = summary,code = code,user = u)

class EditPost(Handler):
    def get(self,post_id):
        u = self.check_id_cookie()
        if not u:
            redirect('/login')
        e = PostObject.get_by_id(int(post_id))
        self.render('newpost.html',title = e.title,summary = e.summary, code = e.code, user = u)

    def post(self,post_id):
        logging.info('post id is: '+post_id)
        u = self.check_id_cookie()
        if not u:
            redirect('/login')
        e = PostObject.get_by_id(int(post_id))
        title = self.request.get('subject')
        summary = self.request.get('summary')
        code = self.request.get('content')

        if title and code and summary:
            e.title = title
            e.summary = summary
            e.code = code
            e.posted_by = u.username
            e.put()
            self.redirect('../'+post_id)
        else:
            self.render('newpost.html',error_message = 'All fields are required!',title = title,summary = summary,code = code,user = u)

class DeletePost(Handler):
    def get(self,post_id):
        u = self.check_id_cookie()
        if not u:
            redirect('/login')
        e = PostObject.get_by_id(int(post_id))
        e.delete()
        time.sleep(0.4)
        self.redirect('/welcome')

class LikePost(Handler):
    def get(self,post_id):
        u = self.check_id_cookie()
        if not u:
            self.redirect('/login')
        e = PostObject.get_by_id(int(post_id))
        if u.username in e.likes:
            e.likes.remove(u.username)
        else:
            e.likes.append(u.username)
        e.put()
        # self.redirect('/')

class Entery(Handler):
    def get(self,post_id):
        u = self.check_id_cookie()
        entry = PostObject.get_by_id(int(post_id))

        self.render('entery.html',entry = entry,user = u)

class CommentObject(db.Model):
    comment = db.TextProperty(required = True)
    post_id = db.IntegerProperty(required = True)
    poster_id = db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class PostObject(db.Model):
    title = db.StringProperty(required = True)
    summary = db.TextProperty(required = True)
    code = db.TextProperty(required = True)
    posted_by = db.StringProperty(required = True)
    likes = db.StringListProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    likes = db.StringListProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newpost',NewPost),
    ('/([0-9]+)',Entery),
    ('/signup',Signup),
    ('/welcome',Welcome),
    ('/login',Login),
    ('/logout',Logout),
    ('/postsby/([a-zA-Z0-9_-]+)',PostsBy),
    ('/edit/([0-9]+)',EditPost),
    ('/delete/([0-9]+)',DeletePost),
    ('/like/([0-9]+)',LikePost)
], debug=True)








