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

# Allows for the use of jinja2 for the html templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Random string used to hash with user ID to make and set secure cookies
# Part of the string is a date-stamp so secret key changes daily,
# however, this prevents the use of
# a 'Remember Me' checkbox
secret = 'vjdnfjskygr82745489572439hjkjhk84hgfhfhg237y89123hdwjndka' \
    + str(datetime.date.today())


# Helper method used to render a page
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# Method used to validate a new users username
def valid_username(user):
    name = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return user and name.match(user)


# Method used to validate a new users password
def valid_password(password):
    passw = re.compile(r"^.{3,20}$")
    return password and passw.match(password)


# Method used to validate a new users email address
def valid_email(email):
    e = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return email and e.match(email)


# Handler Class that all other handles inherit from
class Handler(webapp2.RequestHandler):
    # Used to write html to page
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    # Used to render a template to the current page
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    # Used to hash a string
    def hash_str(self, some_text):
        hash_text = hashlib.sha256(str(some_text) + secret).hexdigest()
        return hash_text

    # Runs anytime the Handler is called.  Checks for a secure cookie,
    # and if found, verifies the user and returns them
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.check_id_cookie()
        self.u = uid

    # Used to make a salt during new user signup
    def make_salt(self):
        salt = ''
        for i in range(0, 5):
            salt += random.choice(string.letters)
        return salt

    # Hashes new users passwords with a random salt for storing in DB
    # In future implementation I would like to use bcrypt instead of sha
    def hash_password(self, pswd):
        salt = self.make_salt()
        pw_hash = hashlib.sha256(str(pswd) + salt).hexdigest()
        return pw_hash + '|' + salt

    # Verifies a users password when a user logs in
    def verify_password(self, pswd, salt):
        pw_hash = hashlib.sha256(str(pswd) + str(salt)).hexdigest()
        return pw_hash

    # Checks to see if the hash in a cookie is valid
    def verify_cookie(self, val):
        val_a = val.split('|')
        if self.hash_str(val_a[0]) == val_a[1]:
            return val_a[0]

    # Checks if a secure cookie is valid. If it is, it returns the user
    def check_id_cookie(self):
        cookie = self.request.cookies.get('user_id')
        if cookie:
            verification = self.verify_cookie(cookie)
            if verification:
                logging.info("cookie verified")
                u = User.get_by_id(int(verification), parent=None)
                return u

    # Sets a secure cookie when a user logs in
    def set_secure_cookie(self, user_id):
        hash_id = self.hash_str(user_id)
        self.response.headers.add_header('Set-Cookie', 'user_id=%s|%s;PATH=/'
                                         % (user_id, hash_id))

    # Checks for a cookie containing the users recently viewed
    # blog posts and returns them
    def read_recent_cookie(self):
        cookie = self.request.cookies.get('recent')
        if cookie is not None:
            posts = cookie.split('|')
            return posts

    # Adds a blog post to the users list of recently viewed posts
    def add_recent_post(self, post):
        cookie_a = self.read_recent_cookie()
        cookie = str(self.request.cookies.get('recent'))
        logging.info(cookie_a)
        if cookie_a is None:
            cookie = str(post)
        elif post not in cookie_a:
            logging.info('second if ran')
            cookie = self.request.cookies.get('recent')
            cookie = str(post + '|' + cookie)
        self.response.headers.add_header('Set-Cookie',
                                         'recent=%s; PATH=/' % cookie)


# Loads the home page with all recent posts
class MainHandler(Handler):
    def get(self):
        enteries = db.GqlQuery('select * from PostObject '
                               'order by created desc').fetch(limit=None)
        self.render('main.html', enteries=enteries, user=self.u,
                    title='Recent Posts:')


# Handles new user signups
class Signup(Handler):
    def get(self):
        if self.u:
            self.redirect('/welcome')
        else:
            self.render('/signup.html')

    def post(self):
        # Grabs all of the data the user entered into the form
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        # Creates a list of errors to show to user if needed
        params = {'username': username}
        valid_form = True

        # Checks all of the entered info to verify it meets standards
        already_exists = db.GqlQuery(
            "select * from User where username = '%s'" % username).get()
        if already_exists:
            params['error_username'] = 'Username is already taken'
            valid_form = False
        if not valid_username(username):
            params['error_username'] = 'Your username should be between' \
                ' 3-20 characters/numbers'
            valid_form = False
        if not valid_password(password):
            params['error_password'] = 'Your password should be between' \
                ' 3-20 characters/numbers'
            valid_form = False
        if password != verify:
            params['error_verify'] = 'Passwords do not match'
            valid_form = False
        if email:
            if not valid_email(email):
                params['error_email'] = 'Not a valid email address'
                valid_form = False

        # If all data is valid, hashes the password and sores all
        # of the data in the DB as a User
        if valid_form:
            hash_password = self.hash_password(password)
            new_user = User(username=username,
                            password=hash_password,
                            email=email,
                            likes=[])
            new_user_key = new_user.put()
            user_id = new_user_key.id()
            self.set_secure_cookie(user_id)
            self.redirect('/welcome')
        else:
            # If something does not meet standards,
            # reloads the page and displays the needed error message
            self.render('signup.html', **params)


# Handles all logins
class Login(Handler):
    def get(self):
        if self.u:
            self.redirect('/welcome')
        else:
            self.render('/login.html')

    def post(self):
        # Gets the username and password from form
        username = self.request.get('username')
        password = self.request.get('password')
        # Finds the user in the database
        user = db.GqlQuery("select * from User where username = '%s'"
                           % username).get()
        if user:
            # Checks the hased password with the stored password
            pw_hash = user.password.split('|')
            if self.verify_password(password, pw_hash[1]) == pw_hash[0]:
                # If password is verified, cookie is set and user
                # is redirected to the welcome page
                self.set_secure_cookie(user.key().id())
                self.redirect('/welcome')
            else:
                # Alerts the user that their username/password is wrong
                self.render('login.html',
                            username=username,
                            error='Invalid username and/or password')

        else:
            # Alerts the user that their username/password is wrong
            self.render('login.html',
                        username=username,
                        error='Invalid username and/or password')


# Logs out the user by deleting the cookie
class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=;PATH=/')
        self.redirect('/login')


# Grabs all posts from the current user and loads them for review
class Welcome(Handler):
    def get(self):
        if self.u:
            posts = db.GqlQuery("select * from PostObject where posted_by =" +
                                " '%s' order by created desc" %
                                self.u.username).fetch(limit=None)
            self.render('main.html', user=self.u, enteries=posts,
                        title='Your Posts:')
        else:
            self.redirect('/login')


# Grabs all posts by a given user and lists them all on one page
class PostsBy(Handler):
    def get(self, poster):
        user = self.check_id_cookie()
        posts = db.GqlQuery("select * from PostObject where posted_by ="
                            " '%s' order by created desc" % poster) \
            .fetch(limit=None)
        self.render('main.html',
                    enteries=posts,
                    user=user,
                    title='Posts by ' + poster)


# Handles all new posts
class NewPost(Handler):
    def get(self):
        # Checks for valid user
        if self.u:
            # If found, loads page
            self.render('newpost.html', user=self.u, e=None)
        else:
            # If not found, redirects to login page
            self.redirect('/login')

    def post(self):
        # checks for valid user
        if self.u:
            # grabs data from form
            title = self.request.get('subject')
            summary = self.request.get('summary')
            code = self.request.get('content')
            # Checks to see if data is valid. If it is, it
            # creates a new PostObject and stores it in the DB
            # In my future rollout I would like to use something like 'bleach'
            # to further protect against code injection.
            if title and code and summary:
                new_entery = PostObject(title=title, summary=summary,
                                        code=code, posted_by=self.u.username,
                                        likes=[])
                key = new_entery.put()
                entry_id = '/' + str(key.id()) + '/0'
                logging.info(entry_id)
                # Redirects user to view their new blog post
                self.redirect(entry_id)
            else:
                self.render('newpost.html',
                            error_message='All fields are required!',
                            title=title,
                            summary=summary,
                            code=code,
                            user=self.u)
        else:
            self.redirect('/login')


# Handles editing a blog post
class EditPost(Handler):
    def get(self, post_id):
        if self.u:
            # Grabs the post from the DB
            e = PostObject.get_by_id(int(post_id))
            # Verifies that the post was posted by the current user
            if self.u.username == e.posted_by:
                # Loads the data into the form to allow editing
                self.render('newpost.html', e=e, user=self.u)
            else:
                self.redirect('../' + post_id + '/0')
        else:
            self.redirect('../' + post_id + '/0')

    def post(self, post_id):
        if self.u:
            # Updates all of the data the user entered
            e = PostObject.get_by_id(int(post_id))
            title = self.request.get('subject')
            summary = self.request.get('summary')
            code = self.request.get('content')
            if e.posted_by == self.u.username:
                # Checks if data is valid
                # Would like to use something like bleach in future updates
                if title and code and summary:
                    e.title = title
                    e.summary = summary
                    e.code = code
                    # Updates the object in the DB
                    e.put()
                    self.redirect('../' + post_id + '/0')
                else:
                    self.render('newpost.html',
                                error_message='All fields are required!',
                                title=title,
                                summary=summary,
                                code=code,
                                user=self.u)
            else:
                self.redirect('/login')
        else:
            self.redirect('/login')


# Handles deleting posts and comments
class DeletePost(Handler):
    def post(self, type, post_id):
        # Checks for a valid user
        if self.u:
            o = None
            e = False
            # Checks if a blog post or comment is being deleted
            if type == 'post':
                # Grabs the PostObject to delete
                o = PostObject.get_by_id(int(post_id))
                # Verifies the author is the current user
                if o.posted_by == self.u.username:
                    # Grabs all comments from this blog post
                    # and deletes them and then deletes the PostObject
                    comments = db.GqlQuery("select * from CommentObject " +
                                           "where post_id = '%s'" % post_id) \
                        .fetch(limit=None)
                    for c in comments:
                        c.delete()
                    o.delete()
                else:
                    self.redirect('/' + post_id + '/0')
            elif type == 'comment':
                # Grabs the comment that is to be deleted
                # as well as the PostObject it belogs to
                o = CommentObject.get_by_id(int(post_id))
                e = PostObject.get_by_id(int(o.post_id))
                # Verifies the comment was authored by the current user
                if o.posted_by == self.u.username:
                    o.delete()
                else:
                    self.redirect('/' + e.post_id + '/0')
            # Short delay to allow the DB to process
            # the request before the page reloads
            # (if there was a callback method I would use that instead)
            time.sleep(0.3)
            # Redirects to either the welcome page or the orginal blog post
            if e:
                self.redirect('/' + str(e.key().id()) + '/0')
            else:
                self.redirect('/welcome')
        else:
            self.redirect('/login')


# Handles when a user likes a post or a comment
class LikePost(Handler):
    def post(self, type, object_id):
        # Checks for a valid user
        if self.u:
            o = None
            e = False
            # Checks if user is liking a post
            # or a comment and grabs the objects
            if type == 'post':
                o = PostObject.get_by_id(int(object_id))
            elif type == 'comment':
                o = CommentObject.get_by_id(int(object_id))
                e = PostObject.get_by_id(int(o.post_id))
            if self.u.username != o.posted_by:
                # Checks to see if the user has already
                # liked the post. If so, it 'unlikes' it by
                # removing their name from the 'like' list.
                # Otherwise it adds them to the 'like' list
                if self.u.username in o.likes:
                    o.likes.remove(self.u.username)
                    self.u.likes.remove(str(object_id))
                else:
                    o.likes.append(self.u.username)
                    self.u.likes.append(str(object_id))
                # Updates the object and the users in the DB
                o.put()
                self.u.put()
                # Short delay to allow the DB to process
                # the update before the next page loads
                time.sleep(0.3)
                # Redirects the user back to the original blog post page
            if e:
                self.redirect('/' + str(e.key().id()) + '/0')
            else:
                self.redirect('/' + object_id + '/0')
        else:
            self.redirect('/login')


# Displays a page with all of the posts the user has 'liked'
class LikedPosts(Handler):
    def get(self):
        # Checks for a valid user
        if self.u:
            # Grabs a list of all of the posts/comments the user has liked
            posts = self.u.likes
            entries = []
            for post in posts:
                # Grabs the post from the DB
                e = PostObject.get_by_id(int(post))
                # Filters out all of the comments
                if e is not None:
                    entries.append(e)
                    logging.info(entries)
            # Renders the page with the list of liked posts
            self.render('/main.html',
                        enteries=entries,
                        user=self.u,
                        title='Liked Posts:')
        else:
            self.redirect('/login')


# Displays a page with all of the posts the user has recently visited
class RecentPosts(Handler):
    def get(self):
        # Gets a list of recent posts from the 'recent' cookie, if it exists
        posts = self.read_recent_cookie()
        entries = []
        # Creats a list of post IDs from the cookie
        if posts is not None:
            for post in posts:
                # Grabs each post and adds them to the list
                e = PostObject.get_by_id(int(post))
                if e is not None:
                    entries.append(e)
                    logging.info(entries)
        # Renders the page with the list of recent posts
        self.render('/main.html',
                    enteries=entries,
                    user=self.u,
                    title='Recently Viewed:')


# Handles showing one single blog post with all comments
class Entery(Handler):
    def get(self, post_id, comment_id):
        # Adds the current blog post to the 'recent' cookie
        self.add_recent_post(str(post_id))
        # Gets the current blog post and all of its comments
        e = PostObject.get_by_id(int(post_id))
        comments = db.GqlQuery("select * from CommentObject " +
                               "where post_id = '%s' order by created"
                               % post_id).fetch(limit=None)
        # renders the page
        self.render('entery.html',
                    e=e,
                    user=self.u,
                    comments=comments,
                    comment_id=int(comment_id))

    # Handles posting/editing comments to a blog post
    def post(self, post_id, comment_id):
        # Checks for valid user
        if self.u:
            # Gets the comment from the form
            comment = self.request.get('comment')
            if comment:
                # Checks if user is posting new comment or editing comment
                # '0' indicates a new comment
                if comment_id == '0':
                    # Creates new comment object and saves it to the DB
                    c = CommentObject(comment=comment,
                                      post_id=post_id,
                                      posted_by=self.u.username,
                                      likes=[])
                    c.put()
                    # Small delay to allow DB to update before reloading page
                    time.sleep(.3)
                # Editing an existing comment
                else:
                    # Gets comment and verifies that its author
                    # is the current user
                    c = CommentObject.get_by_id(int(comment_id))
                    if c.posted_by == self.u.username:
                        # Updates the comment and saves it
                        c.comment = comment
                        c.put()
                        # Small delay to allow DB to update
                        # before reloading page
                        time.sleep(0.3)
                    else:
                        self.redirect('/' + post_id + '/0')
            self.redirect('/' + post_id + '/0')
        else:
            self.redirect('/login')


# Defines a comment object
class CommentObject(db.Model):
    comment = db.TextProperty(required=True)
    post_id = db.StringProperty(required=True)
    posted_by = db.StringProperty(required=True)
    likes = db.StringListProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


# Defines a PostObject
class PostObject(db.Model):
    title = db.StringProperty(required=True)
    summary = db.TextProperty(required=True)
    code = db.TextProperty(required=True)
    posted_by = db.StringProperty(required=True)
    likes = db.StringListProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


# Defines a User
class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()
    likes = db.StringListProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


# All of the redirects
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newpost', NewPost),
    ('/([0-9]+)/([0-9]+)', Entery),
    ('/signup', Signup),
    ('/welcome', Welcome),
    ('/login', Login),
    ('/logout', Logout),
    ('/postsby/([a-zA-Z0-9_-]+)', PostsBy),
    ('/edit/([0-9]+)', EditPost),
    ('/delete/([a-z]+)/([0-9]+)', DeletePost),
    ('/like/([a-z]+)/([0-9]+)', LikePost),
    ('/likedposts', LikedPosts),
    ('/recentposts', RecentPosts)
], debug=True)
