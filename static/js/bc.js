$.get( "/gPostInfo/?name_post=PY1", function( data ) {
 $('div#picture_id').css('background-image', 'url(/static/img/bg-img/' + data.picture_id + ')');
 $('a#picture_title').html(data.title)
 $('a span#picture_author').html(data.author)
 $('a span#picture_date').html(data.created_on)
 $('a span#picture_cm').html(data.total_cm)
 $('a span#picture_like').html(data.total_like)
});