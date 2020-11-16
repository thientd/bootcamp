from django.shortcuts import render
from django.http import HttpResponse
from django.http import JsonResponse
from django.shortcuts import render
import pickle
import base64
from django.contrib import messages
from vul_web.models import *
from vul_web.rce.post import *
from datetime import datetime, timedelta
from django.views.decorators.csrf import csrf_protect
from django.utils.crypto import get_random_string
import hashlib
from django.core.mail import send_mail
from django.conf import settings
from vul_web.Encrypt import encrypt
from vul_web.Encrypt import config
from django.shortcuts import redirect
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session


def homePageView(request):
    if request.method == 'GET':
        page2_query = "select * from vul_web_infopost where tag ='page2'"
        page_query_ex = InfoPost.objects.raw(page2_query)
        data_page2 = {"page_data": page_query_ex}
        print(data_page2)
        return render(request, 'index.html', data_page2)


def getInfoPost(request):
    if request.method == 'GET':
        data_res = {}
        name_post = request.GET.get("name_post")
        bl = ['"']
        if name_post.find('"') != -1:
            data_res["message"] = "attack detected"
            return JsonResponse(data_res)
        query_string = 'select * from vul_web_infopost where tag="' + name_post + '"'
        querydata = InfoPost.objects.raw(query_string)
        for item in querydata:
            data_res["author"] = item.author
            data_res["title"] = item.title
            data_res["total_cm"] = item.total_cm
            data_res["total_like"] = item.total_like
            data_res["created_on"] = item.created_on
            data_res["picture_id"] = item.picture_id
        return JsonResponse(data_res)


def gComment(request):
    data_comment = base64.urlsafe_b64decode(request.GET.get("data_comment"))
    deserialized = pickle.loads(data_comment)
    data_res = {"message": "OK"}
    return JsonResponse(data_res)


def sPost(request):
    return render(request, 'contact.html')


def sPost_process_new_post(request):
    if request.method == "POST":
        image = request.FILES['filename']
        image_name = image.name
        new_post = POST(
            request.POST.get('name'),
            request.POST.get('phone'),
            request.POST.get('email'),
            request.POST.get('message'),

            image_name,
            request.POST.get('title'),
        )
        save_note(new_post, image)
        file_name_hash = new_post.internal_title
        message_ = "Đã gửi bài viết thành công, mã bài viết: " + str(file_name_hash)
        messages.success(request, message_)

    return render(request, 'contact.html')


def feedback(request):
    return render(request, 'contact2.html')


def register(request):
    return render(request, 'register.html')


@csrf_protect
def processfeedback(request):
    if request.method == "POST":
        feed_name = request.POST.get("name")
        feed_email = request.POST.get("email")
        feed_message = request.POST.get("message")
        insert_feed = Feed(name=feed_name, email=feed_email, message=feed_message)
        insert_feed.save()
        message_ = "Cảm ơn bạn đã gửi góp ý. BQT sẽ kiểm tra và phản hồi lại bạn! "
        messages.success(request, message_)

    return render(request, 'contact2.html')


@csrf_protect
def processAccount(request):
    if request.method == "POST":
        user_name = request.POST.get("username")
        user_pass = request.POST.get("password")
        user_email = request.POST.get("email")
        user_phone = request.POST.get("phonenumber")
        user_pass_hashed = hashlib.sha256(str(user_pass).encode()).hexdigest()
        email_hashed = hashlib.sha256(str(user_email).encode()).hexdigest()
        try:
            check_email = User.objects.filter(email=user_email)
            check_user = User.objects.filter(name=user_name)
            if (check_email):
                error_message = "Email đã được đăng ký"
                messages.success(request, error_message)
                return redirect("/register/")
            if (check_user):
                error_message = "Tài khoản đã được đăng ký"
                messages.success(request, error_message)
                return redirect("/register/")
            insert_feed = User(user_id=email_hashed, name=user_name, phone=user_phone, email=user_email,
                               password=user_pass_hashed)
            insert_feed.save()
            message_ = "Đăng ký tài khoản thành công"
            messages.success(request, message_)
        except Exception as e:
            message_ = "Đăng ký không thành công"
            messages.success(request, message_)
    return redirect("/register/")


def profile(request):
    return render(request, 'user_profile.html')


def show_post_detail(request):
    post = unpickle_file(request.GET.get("post_id"))
    try:
        post_data = {
            "name": post.name[0],
            "title": post.title,
            "image": post.image_filename,
            "message": post.message[0]
        }
    except Exception as e:
        post_data = {}
        print(e)
    # print(post_data)
    # page_data = {"post_data":post_data}
    # print(page_data)
    return render(request, 'video-post.html', post_data)


def downloadImage(request):
    file_name = request.GET.get("img_id")
    f = open("static\\img\\bg-img\\" + file_name, "rb")

    b64_img = base64.b64encode(f.read())

    data_res = {
        "img_file": b64_img.decode("utf-8")
    }
    print(data_res)
    f.close()
    return JsonResponse(data_res)


def check_session_timeout(session_time_stamp):
    now = datetime.now()
    ts_now = datetime.timestamp(now)
    if session_time_stamp > ts_now:
        return True
    else:
        return False


def admin(request):
    if request.COOKIES.get("JESSIONID"):
        session_id = request.COOKIES.get("JESSIONID")
        if (session_id == "24cbb434eb0b4c9950700ef495bb2c5f"):
            feed_back = Feed.objects.all()
            data_feed = {"data_feed": feed_back}

        return render(request, 'user_profile.html', data_feed)
        else:
            return redirect("/login/")


def login(request):
    if request.COOKIES.get("JESSIONID"):
        session_user = SessionStore(session_key=request.COOKIES.get("JESSIONID"))
        # print(session_user.session_data
        print(session_user["timeout"])
        if check_session_timeout(session_user["timeout"]):
            checkuser = User.objects.filter(email=session_user["username"])
            if checkuser:
                user_info = {
                    "username": checkuser[0].email
                }
                response = render(request, 'user_profile.html', user_info)
                return response

    return render(request, 'login.html')


@csrf_protect
def processlogin(request):
    if request.method == "POST":
        create_new_session = SessionStore()
        login_email = request.POST.get("email")
        login_password = request.POST.get("pass")
        login_password_hashed = hashlib.sha256(str(login_password).encode()).hexdigest()
        login_user = User.objects.filter(email=login_email)
        if (login_user):
            if (login_user[0].password == login_password_hashed):
                now = datetime.now()
                session_time_out = now + timedelta(minutes=1)
                ts = datetime.timestamp(session_time_out)
                create_new_session["username"] = login_email
                create_new_session["timeout"] = ts
                create_new_session.save()
                create_new_session.create()
                user_info = {
                    "username": login_email
                }
                response = render(request, 'user_profile.html', user_info)
                response.set_cookie('JESSIONID', create_new_session.session_key)
                return response
            else:
                message_ = "Mật khẩu bạn nhập không đúng"
                messages.error(request, message_)
                # error_message = "Email đã được đăng ký"
                # messages.success(request, error_message)
                return redirect("/login/")
        else:
            message_ = "Tài khoản không tồn tại"
            messages.error(request, message_)
            return redirect("/login/")
    return redirect("/login/")


def send_email(subject, message, recipient_list):
    email_from = settings.EMAIL_HOST_USER
    send_mail(subject, message, email_from, recipient_list)
    return 1


def generate_token(account):
    salt_key = config.SALT_KEY + "_" + account
    salt_key_encrypted = encrypt.ecb_mode(salt_key.encode())
    print(salt_key_encrypted)
    salt_key_string = ""
    for i in salt_key_encrypted:
        salt_key_string += str(i)
    print(salt_key_string)
    return salt_key_string


@csrf_protect
def resetpass(request):
    if request.method == "POST":
        user = request.POST.get("username")
        email = request.POST.get("email")
        user_request_reset = User.objects.filter(email=email)
        if (user_request_reset):
            for i in user_request_reset:
                if (i.email == email):
                    reset_user = resetpassword2.objects.filter(user_id=i.user_id)
                    if (reset_user):
                        # send the reseting email to user
                        now = datetime.now()
                        if (reset_user[0].status == "resetting" and now < datetime.strptime(reset_user[0].timeout_token,
                                                                                            "%Y-%m-%d %H:%M:%S.%f")):
                            email_content = "Chào bạn1 " + i.name
                            email_content += "\r\n Để reset mật khẩu bạn hãy click vào đây: <a href='http://127.0.0.1/resetpassword?token=>" + \
                                             reset_user[0].token + "'>Đặt lại mật khẩu</a>"
                            send_email("Khôi phục mật khẩu", email_content, [email])
                            message_ = "Đã gửi thành công token đến email của bạn"
                            messages.success(request, message_)
                        else:
                            now = datetime.now()
                            time_out = now + timedelta(minutes=10)
                            token_hash = generate_token(user)
                            reset_user_insert = resetpassword2.objects.get(user_id=i.user_id)
                            reset_user_insert.status = "resetting"
                            reset_user_insert.token = token_hash
                            reset_user_insert.timeout_token = time_out
                            reset_user_insert.save()
                            email_content = "Chào bạn2 " + i.name
                            email_content += "\n Để reset mật khẩu bạn hãy click vào đây: " \
                                             "<html>" \
                                             "<a href='http://127.0.0.1/resetpassword?token=>" + token_hash + "'>Đặt lại mật khẩu</a>" \
                                                                                                              "</html>"
                            send_email("Khôi phục mật khẩu", email_content, [email])
                            update_satus = resetpassword2.objects.get(user_id=i.user_id)
                            update_satus.status = "resetting"
                            update_satus.save()
                            message_ = "Đã gửi thành công token đến email của bạn"
                            messages.success(request, message_)
                    else:
                        now = datetime.now()
                        time_out = now + timedelta(minutes=10)
                        token_hash = generate_token(user)
                        reset_user_insert = resetpassword2(user_id=i.user_id, status="resetting", token=token_hash,
                                                           timeout_token=time_out)
                        reset_user_insert.save()
                else:
                    message_ = "email không tồn tại"
                    messages.error(request, message_)
        else:
            message_ = "user không tồn tại"
            messages.error(request, message_)
        return render(request, 'reset_password.html')
    return render(request, 'reset_password.html')
