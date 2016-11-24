import webapp2
import jinja2
import os
from google.appengine.ext import db
import re
import logging

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape=True)

entry_key = 'sample'

class codeobject(db.Model):
	title = db.StringProperty(required = True)
	code = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

def render_str(template,**params):
	t = jinja_env.get_template(template)
	return t.render(params)

class Handler(webapp2.RequestHandler):
	def write(self,*a,**kw):
		self.response.out.write(*a,**kw)

	def render(self,template,**kw):
		self.response.out.write(render_str(template,**kw))

class MainHandler(Handler):
    def get(self):
    	enteries = db.GqlQuery('select * from codeobject order by created')
        self.render('main.html',enteries = enteries)

    
class NewPost(Handler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        title = self.request.get('title')
        code = self.request.get('code')
        if title and code:
            new_entery = codeobject(title = title, code = code)
            # key = new_entery.put()
            # entry_key = '/'+str(key).replace('-','')
            logging.info(entry_key)
            self.redirect('/entery')
        else:
            logging.info('Error with post')
            self.redirect('/')

class Entery(Handler):
    def get(self):
        logging.info("get method ran")
        self.render('entery.html')

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newpost',NewPost),
    ('/entery',Entery)
], debug=True)
