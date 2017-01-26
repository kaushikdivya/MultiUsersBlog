# MultiUsersBlog

**URL Handlers**
 - [Login Page](https://multiusersblog.appspot.com/login)
 - [Signup Page](https://multiusersblog.appspot.com/signup)
 - [All Blogs Page](https://multiusersblog.appspot.com/blog)
 - [Your Own Blogs](https://multiusersblog.appspot.com/see_your_posts)
 - [Your Favorite Blogs](https://multiusersblog.appspot.com/all_fav_posts)
 - [New Blogs](https://multiusersblog.appspot.com/blog/newpost)
 - [Logout Page](https://multiusersblog.appspot.com/signup)
 
**Signup**
 - Username(required) restriction: user name should be atleast 3 character long and should not contain whitespace.
 - Password(required) restriction: Password and Verified password should match.
 - Email(optional) restriction: Should have @ and .com.
 
**Password**
 - Passwords are stored with randon salt and hash value.

**Login**
 - User can login with registered uername and password.
 - User should have valid cookie to perform further any tasks.

**Blogs**
- user blog
  - User should have valid cookie to perform further any tasks.
  - User can view their blogs on specific url.
  - User can only edit or delete their blogs.
  
- all blogs
  - User should have valid cookie to perform further any tasks.
  - All blogs are posted on /blogs.

**Blog comments**
 - User should have valid cookie to perform further any tasks.
 - User can comment on any blog.
 - User can only edit or delete their own comments.

**Likes Blogs**
 - User should have valid cookie to perform further any tasks.
 - User can only like blogs posted by others.
 
**Favorite Blogs**
 - User should have valid cookie to perform further any tasks,
 - User can make any blog as their Favorite including their own.

**Logout**
 - User should have valid cookie to perform further any tasks.
 - Once User logs out, they cannot revisit other pages without loggin. Cookies are deleted on Logout.
