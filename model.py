import logging

from google.appengine.ext import db

class User(db.Model):
    """User Data Entities defined"""
    name = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.EmailProperty()
    created = db.DateTimeProperty(auto_now_add = True)

class Blog(db.Model):
    """Blog Data Entities defined"""
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    modified = db.DateTimeProperty(auto_now = True)
    name = db.ReferenceProperty(User, collection_name='by_user')
    likes_count = db.IntegerProperty()

    def liked_by_user(self, user):
        """Increment like counts"""
        if self.likes_count is None:
            self.likes_count = 1
        else:
            self.likes_count += 1
        self.put()
        UserLikes(user=user, blog=self).put()

class UserLikes(db.Model):
    """User Like Count Data Entities defined"""
    user = db.ReferenceProperty(User, collection_name='liked_by_user')
    blog = db.ReferenceProperty(Blog, collection_name='blog_liked')
    liked_time = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def user_has_liked(cls, user, blog):
        """Checks whether user has already liked the blog or not"""
        if db.GqlQuery("select * from UserLikes where user = :1 and blog = :2", user, blog).count():
            return True
        else:
            return False

class UserFavs(db.Model):
    """User Favorite Blog Entities defined"""
    user = db.ReferenceProperty(User, collection_name='favs_by_user')
    blog = db.ReferenceProperty(Blog, collection_name='blog_fav')
    fav_time = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def update_fav(cls, user, blog, fav_state):
        """Updated User Favorite blog list (Add/Remove)"""
        if db.GqlQuery("select * from UserFavs where  user = :1 and blog = :2", user, blog).count():
            fav_state = False
            db.GqlQuery("select * from UserFavs where  user = :1 and blog = :2", user, blog).get().delete()
            return fav_state
        else:
            fav_state = True
            UserFavs(user=user, blog=blog).put()
            return fav_state

class UserComment(db.Model):
    """User Comment Entities defined"""
    user = db.ReferenceProperty(User, collection_name='comment_by_user')
    blog = db.ReferenceProperty(Blog, collection_name='blog_comment')
    comment = db.TextProperty(required = True)
    created_time = db.DateTimeProperty(auto_now_add = True)
    modified_time = db.DateTimeProperty(auto_now = True)
