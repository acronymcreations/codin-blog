import webapp2
import jinja2
import os
from google.appengine.ext import db
import re
import logging
import hashlib
import time
import random
import string
import datetime

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape=True)

secret = 'vjdnfjskygr8274592yuehdjbfabbhbhgfhfhg237y89123hdwjndka' + str(datetime.date.today())

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

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.check_id_cookie()
        self.u = uid

    def make_salt(self):
        salt = ''
        for i in range(0,5):
            salt += random.choice(string.letters)
        return salt

    def hash_password(self,pswd):
        salt = self.make_salt()
        pw_hash = hashlib.sha256(str(pswd)+salt).hexdigest()
        return pw_hash + '|' + salt

    def verify_password(self,pswd,salt):
        pw_hash = hashlib.sha256(str(pswd) + str(salt)).hexdigest()
        return pw_hash

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

    def get_user(self):
        u = self.check_id_cookie()
        if u is None:
            return self.redirect('/login')
        else:
            return u

    def set_secure_cookie(self,user_id):
        hash_id = self.hash_str(user_id)
        self.response.headers.add_header('Set-Cookie','user_id=%s|%s;PATH=/'%(user_id,hash_id))

    def read_recent_cookie(self):
        cookie = self.request.cookies.get('recent')
        if cookie is not None:
            posts = cookie.split('|')
            return posts

    def add_recent_post(self,post):
        cookie_a = self.read_recent_cookie()
        cookie = str(self.request.cookies.get('recent'))
        logging.info(cookie_a)
        if cookie_a is None:
            cookie = str(post)
        elif not post in cookie_a:
            logging.info('second if ran')
            cookie = self.request.cookies.get('recent')
            cookie = str(post + '|' + cookie)  
        self.response.headers.add_header('Set-Cookie','recent=%s;PATH=/'%cookie)

class MainHandler(Handler):
    def get(self):
    	enteries = db.GqlQuery('select * from PostObject order by created desc').fetch(limit=None)
        self.render('main.html',enteries = enteries, user = self.u,title = 'Recent Posts:')

class Signup(Handler):
    def get(self):
        if self.u:
            self.redirect('/welcome')
        else:
            self.render('/signup.html')


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
            params['error_username'] = 'Your username should be between 3-20 characters/numbers'
            valid_form = False
        if not valid_password(password):
            params['error_password'] = 'Your password should be between 3-20 characters/numbers'
            valid_form = False
        if password != verify:
            params['error_verify'] = 'Passwords do not match'
            valid_form = False
        if email:
            if not valid_email(email):
                params['error_email'] = 'Not a valid email address'
                valid_form = False

        if valid_form:
            hash_password = self.hash_password(password)
            logging.info(hash_password)
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
        if self.u:
            self.redirect('/welcome')
        else:
            self.render('/login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        user = db.GqlQuery("select * from User where username = '%s'"%username).get()
        if user:
            pw_hash = user.password.split('|')
            if self.verify_password(password,pw_hash[1]) == pw_hash[0]:
                logging.info('user is authenticated')
                self.set_secure_cookie(user.key().id())
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
        if self.u:
            posts = db.GqlQuery("select * from PostObject where posted_by = '%s' order by created desc"%self.u.username).fetch(limit=None)
            self.render('main.html',user = self.u,enteries = posts,title = 'Your Posts:')
        else:
            self.redirect('/login')

class PostsBy(Handler):
    def get(self,poster):
        user = self.check_id_cookie()
        posts = db.GqlQuery("select * from PostObject where posted_by = '%s' order by created desc"%poster).fetch(limit=None)
        self.render('main.html',enteries = posts,user = user,title = 'Posts by '+poster)
   
class NewPost(Handler):
    def get(self):
        if self.u:
            self.render('newpost.html',user = self.u,e = None)
        else:
            self.redirect('/login')

    def post(self):
        if self.u:
            title = self.request.get('subject')
            summary = self.request.get('summary')
            code = self.request.get('content')
            
            if title and code and summary:
                new_entery = PostObject(title = title,summary = summary,code = code,posted_by = self.u.username,likes = [])
                key = new_entery.put()
                entry_id = '/' + str(key.id()) + '/0'
                logging.info(entry_id)
                self.redirect(entry_id)
            else:
                self.render('newpost.html',error_message = 'All fields are required!',title = title,summary = summary,code = code,user = self.u)
        else:
            self.redirect('/login')

class EditPost(Handler):
    def get(self,post_id):
        if self.u:
            e = PostObject.get_by_id(int(post_id))
            if self.u.username == e.posted_by:
                self.render('newpost.html',e = e, user = self.u)
            else:
                self.redirect('../'+post_id+'/0')
        else:
                self.redirect('../'+post_id+'/0')

    def post(self,post_id):
        if self.u:
            e = PostObject.get_by_id(int(post_id))
            title = self.request.get('subject')
            summary = self.request.get('summary')
            code = self.request.get('content')

            if title and code and summary:
                e.title = title
                e.summary = summary
                e.code = code
                e.posted_by = self.u.username
                e.put()
                self.redirect('../'+post_id+'/0')
            else:
                self.render('newpost.html',error_message = 'All fields are required!',title = title,summary = summary,code = code,user = self.u)
        else:
            self.redirect('/login')

class DeletePost(Handler):
    def post(self,type,post_id):
        if self.u:
            o = None
            e = False
            if type == 'post':
                o = PostObject.get_by_id(int(post_id))
                if o.posted_by == self.u.username:
                    comments = db.GqlQuery("select * from CommentObject where post_id = '%s'"%post_id).fetch(limit=None)
                    for c in comments:
                        c.delete()
                    o.delete()
                else:
                    self.redirect('/'+post_id+'/0')
            elif type == 'comment':
                o = CommentObject.get_by_id(int(post_id))
                e = PostObject.get_by_id(int(o.post_id))
                if o.posted_by == self.u.username:
                    o.delete()
                else:
                    self.redirect('/'+e.post_id+'/0')
            time.sleep(0.3)
            if e:
                self.redirect('/'+str(e.key().id())+'/0')
            else:
                self.redirect('/welcome')
        else:
            self.redirect('/login')

class LikePost(Handler):
    def post(self,type,object_id):
        if self.u:
            o = None
            e = False
            if type == 'post':
                o = PostObject.get_by_id(int(object_id))
            elif type == 'comment':
                o = CommentObject.get_by_id(int(object_id))
                e = PostObject.get_by_id(int(o.post_id))
            if self.u.username in o.likes:
                o.likes.remove(self.u.username)
                self.u.likes.remove(str(object_id))
            else:
                o.likes.append(self.u.username)
                self.u.likes.append(str(object_id))
            o.put()
            self.u.put()
            time.sleep(0.3)
            if e:
                self.redirect('/'+str(e.key().id())+'/0')
            else:
                self.redirect('/'+object_id+'/0')
        else:
            self.redirect('/login')

class LikedPosts(Handler):
    def get(self):
        if self.u:
            posts = self.u.likes
            entries = []
            for post in posts:
                e = PostObject.get_by_id(int(post))
                if e is not None:
                    entries.append(e)
                    logging.info(entries)
            self.render('/main.html',enteries = entries, user = self.u,title = 'Liked Posts:')
        else:
            self.redirect('/login')

class RecentPosts(Handler):
    def get(self):
        posts = self.read_recent_cookie()
        entries = []
        if posts is not None:
            for post in posts:
                e = PostObject.get_by_id(int(post))
                if e is not None:
                    entries.append(e)
                    logging.info(entries)
        self.render('/main.html',enteries = entries, user = self.u,title = 'Recently Viewed:')
        
class Entery(Handler):
    def get(self,post_id,comment_id):
        self.add_recent_post(str(post_id))
        e = PostObject.get_by_id(int(post_id))
        comments = db.GqlQuery("select * from CommentObject where post_id = '%s' order by created"%post_id).fetch(limit=None)
        self.render('entery.html',e = e,user = self.u,comments = comments,comment_id = int(comment_id))

    def post(self,post_id,comment_id):
        if self.u:
            comment = self.request.get('comment')
            if comment:
                logging.info('first loop')
                if comment_id == '0':
                    logging.info('first loop 1')
                    c = CommentObject(comment = comment, post_id = post_id, posted_by = self.u.username, likes = [])
                    logging.info('first loop 2')
                    c.put()
                    logging.info('first loop 3')
                    time.sleep(.3)
                else:
                    logging.info('first loop 4')
                    c = CommentObject.get_by_id(int(comment_id))
                    c.comment = comment
                    c.put()
                    time.sleep(0.3)
            self.redirect('/'+post_id+'/0')
        else:
            self.redirect('/login')

class CommentObject(db.Model):
    comment = db.TextProperty(required = True)
    post_id = db.StringProperty(required = True)
    posted_by = db.StringProperty(required = True)
    likes = db.StringListProperty(required = True)
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
    ('/([0-9]+)/([0-9]+)',Entery),
    ('/signup',Signup),
    ('/welcome',Welcome),
    ('/login',Login),
    ('/logout',Logout),
    ('/postsby/([a-zA-Z0-9_-]+)',PostsBy),
    ('/edit/([0-9]+)',EditPost),
    ('/delete/([a-z]+)/([0-9]+)',DeletePost),
    ('/like/([a-z]+)/([0-9]+)',LikePost),
    ('/likedposts',LikedPosts),
    ('/recentposts',RecentPosts)
], debug=True)








