# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import webapp2
import jinja2
import os
import logging
import codecs
import re
from google.appengine.ext import db
import hashlib
import random
import string
import json

from model import User, Blog, UserLikes, UserFavs, UserComment

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def get_data_list(data_obj):
    data = []
    for d in data_obj:
        subject = d.subject
        created = d.created
        content = d.content.replace('\n', '<br>')
        blog_id = d.key().id()
        user_id = d.name.key()
        data.append((subject, created, content, blog_id, user_id))
    return data


def authenticated(f):
    def decorated_func(self, *args, **kwargs):
        user = self.get_user_by_cookie()
        if not user:
            self.redirect('/login')
        else:
            self.request.user = user
            retval = f(self, *args, **kwargs)
            self.request.user = None
            return retval
    return decorated_func


class Handler(webapp2.RequestHandler):
    def write(self, *args, **kw):
        self.response.write(*args, **kw)

    def render_str(self, template, **kw):
        t = jinja_env.get_template(template)
        return t.render(kw)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def make_salt(self):
        return "".join(random.choice(string.letters) for x in range(0, 5))

    def make_hash_pass(self, name, password, salt=None):
        if not salt:
            salt = self.make_salt()
        return "%s|%s" % (hashlib.sha256(name + password + salt).hexdigest(),
                          salt)

    def val_hash_pass(self, name, password, user_hash):
        salt = user_hash.split('|')[1]
        return user_hash == self.make_hash_pass(name, password, salt)

    def get_user_info(self, username):
        return db.GqlQuery("select * from User where name = :1", username)

    def get_user_by_id(self, user_id):
        return User.get_by_id(int(user_id))

    def val_user_and_hash(self, user_id, cookie_hash):
        user = self.get_user_by_id(user_id)
        if user and user.password == cookie_hash:
            return user
        else:
            return None

    def get_user_by_cookie(self):
        cookie = self.request.cookies.get("user_id", None)
        logging.info("cookie = %s...", cookie)
        if cookie == "" or cookie is None or cookie == " ":
            logging.info("I am in user not valid")
            return None
        else:
            logging.info("I am in valid user")
            user_id, hash_val, salt = self.request.cookies.get("user_id")\
                .split('|')
            return self.val_user_and_hash(user_id, hash_val+'|'+salt)


class SignUpPage(Handler):
    """Handler class renders htmls for SignUp page. This handles signup
       http get and post requests"""
    def get(self):
        """Renders signup page on signup http get request"""
        logging.info("I am in signup get method")
        self.render('signup.html')

    def post(self):
        """Validates username, password and email as per the rules.
            1. Username should have 3 or more character and there should
               be no whitespace inbetween.
            2. Password and verify password should match.
            3. Email(optional) should be correct."""
        logging.info("I am in signup post method")
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        name_pattern = re.compile(r"[a-zA-Z0-9_-]{3,20}$")
        pass_pattern = re.compile(r".{3,20}$")
        email_pattern = re.compile(r"[\S]+@[\S]+.[\S]+$")
        error_password = ""  # PS1 - add errors in dict
        error_verify = ""
        error_name = ""
        error_email = ""
        if ' ' in username or not name_pattern.match(username):
            error_name = "That's not a valid username."
        elif db.GqlQuery("select * from User where name = :1", username)\
                .count():
            error_name = "User already exists"
        if not password:
            error_password = "That wasn't a valid password."
        elif password != verify:
            error_verify = "Your passwords didn't match."
        if email and not email_pattern.match(email):
            error_email = "That's not a valid email."
        if error_name or error_password or error_verify or error_email:
            self.render('signup.html', username=username,
                        email=email,
                        error_name=error_name,
                        error_password=error_password,
                        error_verify=error_verify,
                        error_email=error_email)
        else:
            user_hash = self.make_hash_pass(username, password)
            a = User(name=username, password=user_hash)
            a.put()
            cookie_name = '%s|%s' % (a.key().id(), user_hash)
            self.response.headers.add_header('Set-Cookie',
                                             'user_id=%s' % cookie_name)
            self.redirect('/blog')


class LoginPage(Handler):
    """Handler class renders htmls for login page.
       This handles login http get and post requests"""
    def get(self):
        """Renders login page on login http get request"""
        self.render('login.html')

    def post(self):
        """Validates whether user exists and has entered correct password"""
        username = self.request.get('username')
        password = self.request.get('password')
        if not (username and password):
            error = "Invalid Login"
            self.render('/login.html', error=error)
        else:
            user_info = self.get_user_info(username)
            if not user_info.count():
                error = "Invalid Login"
                self.render('/login.html', error=error)
            else:
                user_hash = user_info.get().password
                if self.val_hash_pass(username, password, user_hash):
                    cookie_name = '%s|%s' % (user_info.get().key().id(),
                                             str(user_hash))
                    logging.info("cookie = %s", cookie_name)
                    self.response.headers.add_header('Set-Cookie',
                                                     'user_id=%s' %
                                                     cookie_name)
                    self.redirect('/blog')
                else:
                    error = "Invalid Login"
                    self.render('/login.html', error=error)

    def put(self):
        logging.info("I am in login put method")


class LogoutPage(Handler):
    """Handler logout user and sets cookie to null"""
    def get(self):
        """Renders signup page after user logout and sets cookie to null"""
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/signup')


class BlogPost(Handler):
    """Handler renders blogpost html for new blogs"""
    @authenticated
    def get(self):
        """Render blogpost html for new blog on blogpost http get request"""
        self.render('blogpost.html', user=self.request.user)

    @authenticated
    def post(self):
        """Valdiates user cookie, subject and content sent in the post request.
           On valid user and blog, redirects to all blogs page."""
        subject = self.request.get("subject")
        content = self.request.get("content")
        name = self.request.user.name  # PS1: better name for name
        logging.debug("user = %s", name)
        post_title = "User Post"

        if subject and content:
            a = Blog(subject=subject, content=content, name=self.request.user)
            a.put()
            self.redirect('/blog/%s' % (str(a.key().id())))
        else:
            error = "Both subject and content is required"
            self.render('blogpost.html', error=error,
                        subject=subject,
                        content=content,
                        post_title=post_title,
                        username=self.request.user.name)


class UserBlog(Handler):
    """Renders user blog, adds functionality to edit user blog
       and delete user blog"""
    @authenticated
    def get(self, blog_id):
        """Renders user blog and let them edit their blogs"""
        blog = Blog.get_by_id(int(blog_id))
        logging.debug("user = %s, blog_user = %s" % (
                       self.request.user.key().id(),
                       blog.name.key().id()
                        ))
        if not blog:
            self.response.set_status(400)
            self.redirect('/blog/newpost')
        else:
            edit = self.request.get('edit', False)
            comment_count = UserComment.all().filter('blog =', blog).count()\
                or 0
            blog_comments = UserComment.all().filter('blog =', blog).order(
                '-created_time')
            logging.info("comment_count = %s, blog=%s, edit=%s", comment_count,
                         blog.name, type(str(edit)))
            for c in blog_comments:
                logging.info("user_comments = %s", c.comment)
            likes_count = UserLikes.all().filter('blog =', blog).count() or 0
            if blog.name.key().id() == self.request.user.key().id():
                user_edit_delete_state = True
            else:
                user_edit_delete_state = False
            logging.info("user_edit_state=%s", user_edit_delete_state)
            if self.request.get('edit') == 'true' and\
                    self.request.user.key().id() == blog.name.key().id():
                logging.debug("UserBlog::get edit: {}".format(edit))
                self.render('blogpost.html',
                            post_title="Edit User Post",
                            blog=blog,
                            user=self.request.user)
            else:
                self.render('userpost.html',
                            blog=blog,
                            count=comment_count,
                            likes=likes_count,
                            user_edit_delete_state=user_edit_delete_state,
                            blog_comments=blog_comments,
                            user=self.request.user)

    @authenticated
    def post(self, blog_id):
        """Commits User blog after edit"""
        logging.debug("Blog.get_by_id(int(blog_id)): %s",
                      dir(Blog.get_by_id(int(blog_id))))
        blog = Blog.get_by_id(int(blog_id))
        if not blog:
            self.redirect('/see_your_posts')
        else:
            if self.request.user.key().id() == blog.name.key().id():
                blog.subject = self.request.get('subject')
                blog.content = self.request.get('content')
                blog.put()
                self.redirect('/blog/'+blog_id)
            else:
                self.redirect('/blog/'+blog_id)

    @authenticated
    def delete(self, blog_id):
        """Deletes User blog"""
        blog = Blog.get_by_id(int(blog_id))
        logging.debug("blog = %s", dir(Blog.get_by_id(int(blog_id))))
        if not blog:
            status = 400
            response = {
                "msg": "blog id doesn't exists"
            }
        else:
            if blog.name.key().id() == self.request.user.key().id():
                for l in UserLikes.all().filter('blog =', blog):
                    l.delete()
                for f in UserFavs.all().filter('blog =', blog):
                    f.delete()
                for c in UserComment.all().filter('blog =', blog):
                    c.delete()
                blog.delete()
                response = {
                    "msg": "blog deleted successfully"
                }
                status = 200
            else:
                status = 500
                response = {
                    'msg': 'blog author and logged in user are not same'
                }
        self.response.set_status(status)
        self.response.headers.add_header('content-type',
                                         'application/json',
                                         charset='utf-8')
        self.response.out.write(json.dumps(response))

    @authenticated
    def put(self, blog_id):
        blog = Blog.get_by_id(int(blog_id))
        logging.debug("blog = %s", dir(Blog.get_by_id(int(blog_id))))
        if not blog:
            status = 400
            response = {
                "msg": "blog id doesn't exists"
            }
        else:
            json_body = json.loads(self.request.body)
            logging.debug("json_body: %s", json_body)
            if not json_body:
                logging.info("No json body")
                status = 400
                response = {
                    "msg": "No Json body"
                }
            else:
                state = json_body.get("state", None)
                if state == "comment":
                    comment = json_body.get("comment_content", None)
                    logging.info("state: %s , comment: %s" % (state, comment))
                    user_comment = UserComment(blog=blog,
                                               user=self.request.user,
                                               comment=comment)
                    user_comment.put()
                    count = UserComment.all().filter('blog =', blog).count()\
                        or 0
                    count += 1
                    status = 200
                    response = {
                        'comment_count': count,
                        'comment_id': user_comment.key().id(),
                        'blog_id': user_comment.blog.key().id(),
                        'comment': user_comment.comment,
                        'author': user_comment.user.name,
                        'created': user_comment.created_time.strftime(
                            "%b %d, %Y")
                    }
                elif state == "edit-comment":
                    newComment = json_body.get("comment_content", None)
                    comment_id = json_body.get("comment_id", None)
                    logging.info("state: %s , comment_id: %s" % (state,
                                                                 comment_id))
                    user_comment = UserComment.get_by_id(int(comment_id))
                    logging.info("user_comment = %s", dir(user_comment))
                    if user_comment and self.request.user.key().id() ==\
                            user_comment.user.key().id() and\
                            user_comment.blog.key().id() == blog.key().id():
                        user_comment.comment = newComment
                        user_comment.put()
                        status = 200
                        response = {
                            'msg': 'comment updated successfully'
                        }
                    else:
                        status = 400
                        response = {
                            'msg': '''either comment doesnot exists or
                                    user logged in/blog id and comment
                                    user/blog id are not same.'''
                        }
                else:
                    state = 500
                    response = {
                        "msg": "Not a valid state"
                    }
        self.response.set_status(status)
        self.response.headers.add_header('content-type',
                                         'application/json',
                                         charset='utf-8')
        self.response.out.write(json.dumps(response))


class AllBlogs(Handler):
    """Displays all blogs with like counts for the user.
       Also it tell if the blog is marked favorite by the user.
       It allows user to vote likes for the blogs which are not owned
       by the user and which are not already liked. Also mark/unmark blog
       as favorite"""

    @authenticated
    def get(self):
        """Displays all blogs with like counts for the user.
           Also it tell if the blog is marked favorite by the user"""
        all = Blog.all().order('-created')
        if all.count():
            logging.debug("user = %s", self.request.user.name)
            user_favall = UserFavs.all().filter('user =', self.request.user)
            logging.debug("user_favall= %s", user_favall.count())
            fav_blog_id_list = []
            for u in user_favall:
                logging.debug("user_favall = %s", u.user)
                fav_blog_id_list.append(u.blog.key().id())
                logging.debug("fav_blog_id_list = %s", fav_blog_id_list)
            blog_id_comment_count = {}
            for a in all:
                blog_id_comment_count[a.key().id()] = UserComment.all().filter(
                    'blog =', a).count()
            # comment_count = UserCommentCount.all()
            self.render('allblogs.html',
                        data=all,
                        fav_blog_id_list=fav_blog_id_list,
                        blog_id_comment_count=blog_id_comment_count)
        else:
            self.render('allblogs.html')

    @authenticated
    def put(self, *args, **kwargs):
        """It allows user to vote likes for the blogs which are not owned
           by the user and which are not already liked. Also mark/unmark
           blog as favorite"""

        if self.request.body:
            json_body = json.loads(self.request.body)
            logging.debug("json body = %s", json_body)
            blog_id = json.loads(self.request.body).get('blog_id', None)
            fav_state = json_body.get("fav_state", None)
            incr_like_by = json_body.get("incr_like_by", None)
            if blog_id:
                blog = Blog.get_by_id(int(blog_id))
                if not blog:
                    status = 400
                    response = {
                        "msg": "Blog_id not found"
                    }
                else:
                    # In Favorite state chnage block
                    if fav_state is not None:
                        # toggle fav state-if fav_status is 1 then change to 0
                        fav_state = UserFavs.update_fav(self.request.user,
                                                        blog, fav_state)
                        logging.info("fav_state= %s", fav_state)
                        if fav_state is not None:
                            logging.debug("In favstate success loop")
                            status = 200
                            response = {
                                "fav_state": fav_state
                            }
                        else:
                            logging.debug("In favstate fail loop")
                            status = 400
                            response = {
                                "msg": """fav update unsuccessfull.
                                          Something went wrong"""
                            }
                    # In Like count increase block
                    elif incr_like_by:
                        if self.request.user.key().id() ==\
                                blog.name.key().id():
                            status = 200
                            response = {
                                "msg": "Cannot like your own blog"
                            }
                        else:
                            if not UserLikes.user_has_liked(self.request.user,
                                                            blog):
                                blog.liked_by_user(self.request.user)
                                response = {
                                    "likes_count": blog.likes_count
                                }
                            else:
                                response = {
                                    "msg": "Already liked this blog"
                                }
                            status = 200
                    else:
                        status = 400
                        response = {
                            "msg": """Nothing - Not like increment or
                                      fav_state change request"""
                        }
            else:
                status = 400
                response = {
                    "msg": """Nothing - Not like increment or fav_state
                              change request"""
                }
        else:
            status = 400
            response = {
                "msg": """Nothing - Not like increment or fav_state change
                        request"""
            }
        logging.debug("json status: {}, response: {}".format(status, response))
        self.response.set_status(status)
        self.response.headers.add_header('content-type',
                                         'application/json',
                                         charset='utf-8')
        self.response.out.write(json.dumps(response))


class AllUserFavs(Handler):
    """Displays all favorite marked blogs by user"""
    @authenticated
    def get(self):
        all_favs = UserFavs.all().filter('user =',
                                         self.request.user).order('-fav_time')
        logging.debug("all_fav object: %s",
                      UserFavs.all().filter('user =',
                                            self.request.user).count())
        blog_info = []
        if all_favs.count():
            for userfav in all_favs:
                blog_comment_count = UserComment.all().filter('blog =',
                                                              userfav.blog
                                                              ).count() or 0
                likes_count = UserLikes.all().filter('blog =',
                                                     userfav.blog
                                                     ).count() or 0
                blog_info.append((userfav.blog,
                                  likes_count,
                                  blog_comment_count))
        self.render('all_user_favs.html', blog_info=blog_info, fav_state=True)


class SeeYourPosts(Handler):
    """Displays all blogs owned by user"""
    @authenticated
    def get(self):
        posts = Blog.all().filter('name =', self.request.user)
        user_favall = UserFavs.all().filter('user =', self.request.user)
        logging.debug("user_favall= %s", user_favall.count())
        fav_blog_id_list = []
        for u in user_favall:
            logging.debug("user_favall = %s", u.user)
            fav_blog_id_list.append(u.blog.key().id())
            logging.debug("fav_blog_id_list = %s", fav_blog_id_list)
        blog_id_comment_count = {}
        for a in posts:
            blog_id_comment_count[a.key().id()] = UserComment.all().filter(
                                                        'blog =', a).count()
        self.render('see_your_posts.html',
                    posts=posts,
                    fav_blog_id_list=fav_blog_id_list,
                    blog_id_comment_count=blog_id_comment_count)


class UserBlogComment(Handler):
    """Handler for blog comments"""

    @authenticated
    def get(self, blog_id):
        """Renders all comments for the blog"""
        user = self.request.user
        blog = Blog.get_by_id(int(blog_id))
        blog_comments = UserComment.all().filter('blog =',
                                                 blog).order('created_time')
        logging.info("blog_comments = %s, blog_id_type=%s" % (blog_comments,
                                                              type(blog_id)))
        self.render('comments.html',
                    blog_comments=blog_comments,
                    user=user, blog=blog)

    @authenticated
    def delete(self, blog_id):
        """Deletes comments if user logged in and comment user are same"""
        blog = Blog.get_by_id(int(blog_id))
        logging.info("I am in UserBlogComment delete method")
        if blog:
            comment_id = self.request.get('comment_id', None)
            comment = UserComment.get_by_id(int(comment_id))
            if comment and comment.blog.key().id() == blog.key().id():
                logging.info("I am in comment delete section")
                comment.delete()
                status = 200
                response = {
                    'msg': 'comment deleted successfully'
                }
            else:
                status = 400
                response = {
                    'msg': '''comment doesnot exists or comment blog id and
                              blog id doesnot match'''
                }
        else:
            status = 400
            response = {
                'msg': 'blog id doesnot match in the datastore'
            }
        self.response.set_status(status)
        self.response.headers.add_header('content-type',
                                         'application/json',
                                         charset='utf-8')
        self.response.out.write(json.dumps(response))

    @authenticated
    def put(self, blog_id):
        """Provides edit fucntionality for comments"""
        blog = Blog.get_by_id(int(blog_id))
        comment_id = self.request.get('comment_id', None)
        logging.debug("blog= %s, comment_id=%s, blog_id=%s",
                      blog, comment_id, blog_id)
        logging.debug("request.body= %s", self.request.body)
        if blog and comment_id:
            json_body = json.loads(self.request.body)
            if not json_body:
                status = 400
                response = {
                    'msg': 'json body empty'
                }
            else:
                state = json_body.get('state', None)
                new_comment = json_body.get('comment_content', None)
                if not (state or new_comment):
                    status = 400
                    response = {
                        'msg': 'state or new comment is not in json body'
                    }
                else:
                    if state == 'edit-comment':
                        comment_ref = UserComment.get_by_id(int(comment_id))
                        if comment_ref and self.request.user.key().id()\
                                == comment_ref.user.key().id():
                            comment_ref.comment = new_comment
                            comment_ref.put()
                            status = 200
                            response = {
                                'new_comment': new_comment
                            }
                        else:
                            status = 400
                            response = {
                                'msg': '''comment_id doesnot exists or comment
                                          user and logged user doesnot match'''
                            }
                    else:
                        status = 400
                        response = {
                            'msg': 'state edit-comment not found'
                        }
        else:
            status = 400
            response = {
                'msg': "either blogid doesnot exists or commentid is None"
            }
        self.response.set_status(status)
        self.response.headers.add_header('content-type',
                                         'application/json',
                                         charset='utf-8')
        self.response.out.write(json.dumps(response))


app = webapp2.WSGIApplication(
    [
        ('/signup', SignUpPage),
        ('/login', LoginPage),
        ('/logout', LogoutPage),
        ('/blog/newpost', BlogPost),
        webapp2.Route(r'/blog/<blog_id:\d+>', handler=UserBlog),
        ('/blog', AllBlogs),
        ('/all_fav_posts', AllUserFavs),
        ('/see_your_posts', SeeYourPosts),
        webapp2.Route(r'/blog/<blog_id:\d+>/comments',
                      handler=UserBlogComment),
    ],
    debug=True
)
