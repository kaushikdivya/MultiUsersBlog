jQuery.fn.exists = function() { return this.length>0; }


  $(document).on('focusin', 'div.comment-text', function() {

      var oldText = $(this).text();
      console.log("I am in focus section", {
        'oldText': oldText
      });
      if ($('span.blur').exists()) {
        $('span.blur').remove();
      }

      $(this).parent().prepend('<span class="btn-group pull-right blur">'+
                        '<button type="button" id="saveEditComment" class="btn btn-default btn-xs go" onclick="saveEditComment()">'+
                            '<span class="glyphicon glyphicon-ok" aria-hidden="true"></span></a>'+
                        '</button>'+
                        '<button type="button" id="cancelEditComment" class="btn btn-default btn-xs cancel" onclick="cancelEditComment()">'+
                            '<span class="glyphicon glyphicon-remove " aria-hidden="true"></span>'+
                        '</button>'+
                        '<button type="button" id="deleteComment" class="btn btn-default btn-xs" onclick="deleteComment()">'+
                            '<span class="glyphicon glyphicon-trash " aria-hidden="true"></span>'+
                        '</button>'+
                      '</span>')
    //   var $this = $(this);
    //   if ($this.attr("placeheld")) {
    //     $this.attr("placeheld", null);
    //     $this.text("");
    //     $this.focus();
    //   }
    });

    // $(".comment-text").blur(function() {
    //     console.log("I am in blur section");
    //     $('span.blur').remove();
    //   });



function incrementLikes(blog_id) {
  $.ajax(
    {
      type: "PUT",
      url: "/blog",
      dataType: 'json',
      data: JSON.stringify({
        'blog_id': blog_id,
        'incr_like_by': 1
      }),
      success: function(resp) {       
        if (resp.likes_count) {
          console.log('incrementLikes::success', resp);
          $('#likes-' + blog_id).attr("title", "Your like is counted");
          $('#likes-' + blog_id).tooltip();
          $('#likes-' + blog_id).text(resp.likes_count || 0);
        } else {
          if (resp.msg === "Cannot like your own blog") {
            console.log('incrementLikes::canot like own blog', resp);
            $('#likes-' + blog_id).attr("title", "Can't like your own blog");
            $('#likes-' + blog_id).tooltip();
          } else {
            console.log('incrementLikes::allreadyliked', resp);
            $('#likes-' + blog_id).attr("title", "Already liked this blog");
            $('#likes-' + blog_id).tooltip();
          }
        }
      },
      error: function(error) {
        console.log("incrementLikes::error", error);
      }
    }
  );
}

function deleteBlog(blog_id) {
  var pathname = window.location.pathname;
  console.log("I am in delete session",{
    blog_id: blog_id,
    pathname: pathname
  });
  
  $.ajax({
    type: "DELETE",
    url: "/blog/"+blog_id,
    success: function(resp) {
      console.log("deleteSuccess: :");
      if (pathname === '/see_your_posts') {
        $('#delete-' + blog_id).parents().eq(4).remove();
      }
      else {
        window.location.href= '/see_your_posts';
        $('#delete-' + blog_id).parents().eq(4).remove();
      }   
    },
    error: function(error) {
      console.log('delete::error');
    }
  });
}

function favoriteBlog(blog_id, fav_state) {
  fav_state = fav_state && fav_state === 'True';
  var pathname = window.location.pathname; 
  if (fav_state) {
    console.log("Removing red heart");
    $('#heart-' + blog_id).removeClass("red-heart");
  } else {
    console.log("adding red heart");
    $('#heart-' + blog_id).addClass("red-heart");
  }

  $.ajax({
     type: "PUT",
      url: "/blog",
      dataType: 'json',
      data: JSON.stringify({
        'blog_id': blog_id,
        'fav_state': fav_state
      }),
      success: function(resp) {
        console.log('fav_state::success', resp.fav_state);
        if (resp.fav_state) {
          $('#heart-' + blog_id).addClass("red-heart");
        } else {
          $('#heart-' + blog_id).removeClass("red-heart");
          if (pathname === '/all_fav_posts') {
            $('#heart-' + blog_id).parents().eq(4).remove();
          }
        }
      },
      error: function(error) {
        console.log('fav_state::error', resp.fav_state);
    }
  });
}

function editBlog(blog_id) {
  // console.log("inside editBlog", {
  //   blog_id: blog_id
  // });
  window.location.replace('/blog/' + blog_id + '?edit=true');
}

function readmore(blog_id) {
  console.log("I am here")
  $('#content-blog-' + blog_id).slideToggle();
  var oldText = $('#read-more-' + blog_id).text();
  var newText = $('#read-more-' + blog_id).data('text');
  $('#read-more-' + blog_id).text(newText).data('text',oldText);
}

// function blogComments(blog_id) {
//   console.log("I am in comments");
//   window.location.replace('/blog' + blog_id + '?comment=true');
// }

function commentActivate(blog_id) {
  console.log("I am in userblog comment section",{
    comment_content: $('.comment-content').val()
  });
  var blog_id = blog_id;
  $('span.error-msg').html('');
  if ($('.comment-content').val() === '') {
    $('.error-msg').html("Field can't be empty");
  }
  else {
    var comment = $('.comment-content').val();
    $.ajax({
      type: "PUT",
      url: "/blog/"+blog_id,
      dataType: "json",
      data: JSON.stringify({
        state: "comment",
        comment_content: comment
      }),
      success: function(resp) {
        console.log("I am in comment success section", {
          'comment_id': resp.comment_id,
          'blog_id': resp.blog_id,
          'comment': resp.comment
        })
        $('#comment-' + blog_id).text(resp.comment_count);
        $('.comment-container').prepend('<div class="panel panel-default">'+
                                      '<div class="panel-body">'+
                                        '<div id="comment-'+ resp.comment_id +'" class="comment-text" contenteditable="true" data-comment-id="'+ resp.comment_id + '" data-blog-id="'+resp.blog_id+'" data-original="'+resp.comment+'">'+resp.comment+
                                        '</div>'+
                                        '<h5 class="author">'+ resp.created + ' Author: '+ resp.author +'</h5></div>');
        $('.comment-content').val("");
      },

      error: function(error) {
        console.log("I am in comment error section", {
          error: error
        })
      }
    });
  }
}



function cancelEditComment() {
  var oldText = $('span.blur').siblings('.comment-text').attr('data-original')
  console.log("I am in cancelEdit comment",{
    'oldText': $('span.blur').siblings('.comment-text').attr('data-original'),
    'newText': $('span.blur').siblings('.comment-text').text(),
  });
  $('span.blur').siblings('.comment-text').text(oldText);
  $('span.blur').remove();
}

function saveEditComment(){
  var newText = $('span.blur').siblings('.comment-text').text();
  var oldText = $('span.blur').siblings('.comment-text').attr('data-original')
  var blog_id = $('span.blur').siblings('.comment-text').attr('data-blog-id')
  var comment_id = $('span.blur').siblings('.comment-text').attr('data-comment-id')
  console.log("I am in saveedit section", {
    'blog_id': blog_id,
    'comment_id': comment_id
  });
  if (newText === oldText) {
    console.log("both are same");
  } else {
    console.log("both are not same");
    $.ajax({
      type: "PUT",
      url: "/blog/"+blog_id+"/comments?comment_id="+comment_id,
      beforeSend: function(request) {
        request.setRequestHeader("Content-Type", "application/json; charset=UTF-8");
      },
      dataType: "json",
      data: JSON.stringify({
        state: "edit-comment",
        comment_content: newText
      }),
      success: function(resp) {
        console.log("I am in save edit success section");
        $('span.blur').siblings('.comment-text').text(newText);
        $('span.blur').remove();
      },
      error: function(error) {
        console.log("I am in save edit error function")
      }
    })
  }
}

function deleteComment() {
  console.log("I am in delete secttion")
  blog_id = $('span.blur').siblings('.comment-text').attr('data-blog-id')
  comment_id = $('span.blur').siblings('.comment-text').attr('data-comment-id')
  $.ajax({
    type: "DELETE",
    url: "/blog/"+blog_id+"/comments?comment_id="+comment_id,
    success: function(resp) {
      console.log({
        resp: resp
      });
      $('#comment-' + comment_id).parents().eq(1).remove();
    },
    error: function(error) {
      console.log("I am in delete error section", {
        error: error
      });
    }
  })
}