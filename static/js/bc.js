$.get( "/gPostInfo/?name_post=PY1", function( data ) {
 $('div#picture_id').css('background-image', 'url(/static/img/bg-img/' + data.picture_id + ')');
 $('a#picture_title').html(data.title)
 $('a span#picture_author').html(data.author)
 $('a span#picture_date').html(data.created_on)
 $('a span#picture_cm').html(data.total_cm)
 $('a span#picture_like').html(data.total_like)
 $('input#filename').val(data.picture_id)
});
$('#download').on('click', function () {
    filename = $('input#filename').val()
    $.ajax({
        url: '/downloadImage/?img_id='+filename,
        method: 'GET',
        success: function (data) {
            data_image = data["img_file"];
            var a = document.createElement('a');
            a.href = "data:image/png;base64,"+data_image;
            a.download = filename;
            document.body.append(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
        }
    });
});
function view_detail_post1(){
var post_id = $('input#post_id').val()
window.location ="/show_post_detail?post_id="+post_id
}

function show_config () {
$.get( "/admin/post/show_config", function( data ) {
 $('input#config_username').val(data.username)
 $('input#config_password').val(data.password)
 $('input#config_host').val(data.host)
});

}
function save_config () {
 username = $('input#config_username').val()
 password = $('input#config_password').val()
 host =     $('input#config_host').val()
 data_get = "username="+username+"&password="+password+"&host="+host
    $.get( "/root/savecf?"+data_get, function( data ) {
     $("div#alert_message").html(data.message)
    });

}
function show_key () {
    $.get( "/root/showkey/", function( data ) {
     $("div#alert_message2").html(data.key)
    });

}



