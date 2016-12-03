# Codin-Blog

## Quick Start
#### A live version of this project is avalible at http://codin-blog.appspot.com/

#### To build the project yourself:

1. Download and [install Python](https://www.python.org/downloads/)
2. Downlaod and [install Google App Engine](https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Python) for Python
3. Create a new project through the console.
4. Clone this project into the directory created for your new project.
5. Deploy the project.

## Files

`main.py` Contains all of the Handlers that direct and render each page with the appropriate content.

#### Templates

+ `base.html` Contains the header and footer for the site.  All pages use this template as a means of standardizing the site appearance. 

+ `post_block.html` Contains all of the macros used throughout the entire site, including:

	+ `post` Displays a single blog post with the appropriate like/comment/edit/delete buttons where nessicary

	+ `comment` Displays all of the comments for a blog post as well as the appropriate like/comment/edit/delete buttons where nessicary

	+ `summarypost` Displays a summary of the blog post.  This is used as the header for all blog posts as well as for listing multiple posts

	+ `editpost` Contains the form for creating/editing a blog post

+ `main.html` Most pages use this template to display the proper content

+ `login.html` Contains the form to allow users to log into their account

+ `signup.html` Contains the form to allow new users to create an account

+ `newpost.html` Contains the form to allow logged in users to post new blog posts

+ `entery.html` Contains the framework to display a single blog post in full including all comments

#### css

+ `main_styles.css` Contains all of the css styling for the entire site

+ `05-white-brick.png` The image that is used for the site background