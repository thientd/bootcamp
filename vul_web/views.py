from django.http import JsonResponse
from django.shortcuts import render
import base64
from django.contrib import messages
from vul_web.models import *
from vul_web.rce.post import *
from datetime import datetime, timedelta
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.csrf import csrf_protect
import hashlib
from django.core.mail import send_mail
from django.conf import settings
from vul_web.Encrypt import encrypt
from vul_web.Encrypt import config
from django.shortcuts import redirect
from django.contrib.sessions.backends.db import SessionStore
from vul_web.Encrypt.aes import AESCipher
from vul_web.Encrypt import rsa
import ftplib
import traceback
import binascii
POST_FOLDER = 'static/post/'


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
        # bl = ['"']
        # if name_post.find('"') != -1:
        #     data_res["message"] = "attack detected"
        #     return JsonResponse(data_res)
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


@csrf_protect
def sPost_process_new_post(request):
    if request.method == "POST":
        try:
            image = request.FILES['filename']
            image_name = image.name
            new_post = POST(
                request.POST.get('name'),
                request.POST.get('phone'),
                request.POST.get('email'),
                request.POST.get('message'),

                image_name,
                image_name,
                request.POST.get('title'),
            )
            save_note(new_post, image)
            file_name_hash = new_post.internal_title
            # save info to db
            print(request.POST.get('name'))
            print(request.POST.get('phone'))
            print(request.POST.get('email'))
            print(request.POST.get('message'))
            print(image_name)
            print(request.POST.get('title'))
            info_post = Spost4(
                name=str(request.POST.get('name')),
                phone=str(request.POST.get('phone')),
                email=str(request.POST.get('email')),
                message=str(request.POST.get('message')),
                image_filename=str(image.name),
                title=str(request.POST.get('title')))
            info_post.save()
            message_ = "Đã gửi bài viết thành công, mã bài viết: " + str(file_name_hash)
            messages.success(request, message_)
            return render(request, 'contact.html')
        except Exception as e:
            tb1 = traceback.TracebackException.from_exception(e)
            print(''.join(tb1.format()))
            message_ = "Gửi bài viết không thành công,  vui lòng thử lại"
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
        # block_char = []
        # if feed_message.find(")"):
        #     block_char.append("())")
        # if feed_message.find(")"):
        #     block_char.append(")")
        # if feed_message.find(")"):
        #     block_char.append(")")
        # if feed_message.find(")"):
        #     block_char.append(")")
        # if feed_message.find(")"):
        #     block_char.append(")")
        # str = str.replace("<", "")
        # str = str.replace(">", "")
        # str = str.replace("`", "")
        insert_feed = Feed(name=feed_name, email=feed_email, message=str)
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
    if file_name == "../../flag/flag.png" or file_name == "../../flag/backup.zip" or file_name == "page1_1.jpg":
        f = open("static/img/bg-img/" + file_name, "rb")

        b64_img = base64.b64encode(f.read())

        data_res = {
            "img_file": b64_img.decode("utf-8")
        }
        print(data_res)
        f.close()
        return JsonResponse(data_res)
    else:
        f = open("static/img/bg-img/Flag_in_the_Flag.png", "rb")
        b64_img = base64.b64encode(f.read())
        print(b64_img)
        data_res2 = {
            "img_file": b64_img.decode("utf-8")
        }
        f.close()
        return JsonResponse(data_res2)


def check_session_timeout(session_time_stamp):
    now = datetime.now()
    ts_now = datetime.timestamp(now)
    if session_time_stamp > ts_now:
        return True
    else:
        return False


def admin(request):
    if request.COOKIES.get("JESSIONID"):
        session_user = SessionStore(session_key=request.COOKIES.get("JESSIONID"))
        if check_session_timeout(session_user["timeout"]):
            checkuser = User.objects.filter(email=session_user["username"])
            if checkuser:
                if checkuser[0].email == "bootcamp.ctf@gmail.com":
                    feed_back = Feed.objects.all()
                    data_feed = {
                        "data_feed": feed_back,
                        "username": checkuser[0].email
                    }
                    response = render(request, 'user_profile.html', data_feed)
                    return response
                # else:
                #     user_info = {
                #         "username": checkuser[0].email
                #     }
                #     response = render(request, 'user_profile.html', user_info)
                #     return response

    return render(request, 'login.html')


def show_root(request):
    if request.COOKIES.get("JESSIONID"):
        session_user = SessionStore(session_key=request.COOKIES.get("JESSIONID"))
        if check_session_timeout(session_user["timeout"]):
            checkuser = User.objects.filter(email=session_user["username"])
            if checkuser:
                if checkuser[0].email == "root.bootcamp.2020@gmail.com":
                    user_info = {
                        "username": checkuser[0].email
                    }
                    response = render(request, 'root.html', user_info)
                    return response
                else:
                    user_info = {
                        "username": checkuser[0].email
                    }
                    response = render(request, 'root.html', user_info)
                    return response

    return render(request, 'login.html')


def login(request):
    if request.COOKIES.get("JESSIONID"):
        session_user = SessionStore(session_key=request.COOKIES.get("JESSIONID"))
        if check_session_timeout(session_user["timeout"]):
            checkuser = User.objects.filter(email=session_user["username"])
            if checkuser:
                if checkuser[0].email == "bootcamp.ctf@gmail.com":
                    feed_back = Feed.objects.all()
                    data_feed = {
                        "data_feed": feed_back,
                        "username": checkuser[0].email
                    }
                    response = render(request, 'user_profile.html', data_feed)
                    return response
                elif checkuser[0].email == "root.bootcamp.2020@gmail.com":
                    data_feed = {
                        "username": checkuser[0].email
                    }
                    print("root.bootcamp.2020@gmail.com")
                    return redirect("/root/")
                user_info = {
                        "username": checkuser[0].email
                    }
                response = render(request, 'user_profile.html', user_info)
                return response

    return render(request, 'login.html')


@csrf_exempt
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
                session_time_out = now + timedelta(minutes=10)
                ts = datetime.timestamp(session_time_out)
                create_new_session["username"] = login_email
                create_new_session["timeout"] = ts
                create_new_session.save()
                create_new_session.create()
                user_info = {
                    "username": login_email
                }
                if login_email == "root.bootcamp.2020@gmail.com":
                    response = render(request, 'root.html')
                    response.set_cookie('JESSIONID', create_new_session.session_key)
                    return response
                if login_email == "bootcamp.ctf@gmail.com":
                    feed_back = Feed.objects.all()
                    data_feed = {
                        "data_feed": feed_back,
                        "username": login_email
                    }
                    response = render(request, 'user_profile.html', data_feed)
                    response.set_cookie('JESSIONID', create_new_session.session_key)
                    response.set_cookie('Flag', "Flag_Phu_Yen_Banh_Xeo_1338313313213")
                    return response
                else:
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
                            reset_data = i.user_id+"|"+reset_user[0].token
                            key = rsa.load_key("vul_web/Encrypt/rsa_key.txt")
                            f = open("vul_web/Encrypt/aes_key.txt", "rb")
                            dec_aes_key = rsa.dec_data(f.read(), key)
                            enc_object = AESCipher(str(dec_aes_key))
                            enc_data = enc_object.encrypt(reset_data)
                            enc_res = enc_data.decode('ascii')
                            email_content = "Chào bạn " + i.name
                            email_content += "\r\n Để reset mật khẩu bạn hãy nhập mã sau:" + str(enc_res)
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
                            reset_data2 = i.user_id + "|" + token_hash
                            key = rsa.load_key("vul_web/Encrypt/rsa_key.txt")
                            f = open("vul_web/Encrypt/aes_key.txt", "rb")
                            dec_aes_key = rsa.dec_data(f.read(), key)
                            enc_object = AESCipher(str(dec_aes_key))
                            enc_data = enc_object.encrypt(reset_data2)
                            enc_res = enc_data.decode('ascii')

                            email_content = "Chào bạn " + i.name
                            email_content += "\r\n Để reset mật khẩu bạn hãy nhập mã sau:" + str(enc_res)

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
                        reset_data3 = i.user_id + "|" + token_hash
                        key = rsa.load_key("vul_web/Encrypt/rsa_key.txt")
                        f = open("vul_web/Encrypt/aes_key.txt", "rb")
                        dec_aes_key = rsa.dec_data(f.read(), key)
                        enc_object = AESCipher(str(dec_aes_key))
                        enc_data = enc_object.encrypt(reset_data3)
                        enc_res = enc_data.decode('ascii')

                        email_content = "Chào bạn " + i.name
                        email_content += "\r\n Để reset mật khẩu bạn hãy nhập mã sau:" + str(enc_res)

                        send_email("Khôi phục mật khẩu", email_content, [email])
                        update_satus = resetpassword2.objects.get(user_id=i.user_id)
                        update_satus.status = "resetting"
                        update_satus.save()
                        message_ = "Đã gửi thành công token đến email của bạn"
                else:
                    message_ = "email không tồn tại"
                    messages.error(request, message_)
        else:
            message_ = "user không tồn tại"
            messages.error(request, message_)
        return render(request, 'change_pass.html')
    return render(request, 'reset_password.html')


def processReset(request):
    if request.method == "GET":
        token_req = request.GET.get("token")
        token_req = request.GET.get("token")
        if token_req != "":
            token_info = resetpassword2.objects.filter(token=token_req)
            if token_info:
                data_token = str(token_info[0].user_id) + "|" + token_info[0].token
                #     "user_id": token_info[0].user_id,
                #     "token": token_info[0].token
                # }
                key = rsa.load_key("vul_web/Encrypt/rsa_key.txt")
                f = open("vul_web/Encrypt/aes_key.txt", "rb")
                dec_aes_key = rsa.dec_data(f.read(), key)
                enc_object = AESCipher(str(dec_aes_key))
                enc_data = enc_object.encrypt(data_token)
                data_res = {"sec_data": enc_data.decode('ascii')}
                return render(request, "change_pass.html", data_res)
    return render(request, 'reset_password.html')


def display_reset_pass(request):
    return render(request, 'reset_password.html')


@csrf_protect
def processChangePass(request):
    try:
        username = request.POST.get("email")
        password_new = request.POST.get("password")
        resetcode = request.POST.get("resetcode")
        key = rsa.load_key("vul_web/Encrypt/rsa_key.txt")
        f = open("vul_web/Encrypt/aes_key.txt", "rb")
        dec_aes_key = rsa.dec_data(f.read(), key)
        dec_ob = AESCipher(str(dec_aes_key))
        dec_data = dec_ob.decrypt(resetcode)
        dec_data_split = dec_data.split('|')
        uid = dec_data_split[0]
        token = dec_data_split[1]
        reset_user = User.objects.filter(user_id=uid)
        reset_token = resetpassword2.objects.filter(user_id=uid)
        if reset_user:
            if reset_user[0].email == username:
                if reset_token[0].token == token:
                    user_pass_hashed = hashlib.sha256(str(password_new).encode()).hexdigest()
                    reset_user_pass = User.objects.get(user_id=uid)
                    reset_user_pass.password = user_pass_hashed
                    reset_user_pass.save()
                    message_ = "Đã cập nhật mật khẩu thành công"
                    messages.success(request, message_)
                    return render(request, 'change_pass.html')
        message_ = "Cập nhật mật khẩu không thành công"
    except Exception as e:
        print(str(e))
        message_ = "Cập nhật mật khẩu không thành công"
        messages.success(request, message_)
        return render(request, 'change_pass.html')
    message_ = "Cập nhật mật khẩu không thành công"
    messages.success(request, message_)
    return render(request, 'change_pass.html')


def PostReview(request):
    if request.COOKIES.get("JESSIONID"):
        session_user = SessionStore(session_key=request.COOKIES.get("JESSIONID"))
        if check_session_timeout(session_user["timeout"]):
            checkuser = User.objects.filter(email=session_user["username"])
            if checkuser:
                if checkuser[0].email == "bootcamp.ctf@gmail.com":
                    post_data = Spost4.objects.all()
                    ftp_info = FTP.objects.all()
                    print(ftp_info[0].host)
                    data_post = {"post_data": post_data, "ftp_info": ftp_info}
                    return render(request, 'user_profile2.html', data_post)
                else:
                    return redirect("/login/")
    return redirect("/login/")
    # load data



def authorize(request):
    if request.COOKIES.get("JESSIONID"):
        session_user = SessionStore(session_key=request.COOKIES.get("JESSIONID"))
        if check_session_timeout(session_user["timeout"]):
            checkuser = User.objects.filter(email=session_user["username"])
            if checkuser:
                if checkuser[0].email == "bootcamp.ctf@gmail.com":
                    post_id = request.GET.get("post_id")
                    info_post = Spost4.objects.filter(id=post_id)
                    info_ftp = FTP.objects.all()

                    session = ftplib.FTP(info_ftp[0].host, info_ftp[0].user_name, info_ftp[0].password)
                    file_name = POST_FOLDER + str(info_post[0].image_filename)
                    file = open(file_name, 'rb')  # file to send
                    session.storbinary("STOR input/ " + info_post[0].image_filename, file)  # send the file
                    file.close()  # close file and FTP
                    session.quit()
                    update_status = Spost4.objects.get(id=post_id)
                    update_status.status = True
                    update_status.save()
                    return redirect(PostReview)
                else:
                    return redirect("/login/")
    return redirect("/login/")

def show_config(request):
    if request.COOKIES.get("JESSIONID"):
        session_user = SessionStore(session_key=request.COOKIES.get("JESSIONID"))
        if check_session_timeout(session_user["timeout"]):
            checkuser = User.objects.filter(email=session_user["username"])
            if checkuser:
                if checkuser[0].email == "root.bootcamp.2020@gmail.com":
                    ftp_config = FTP.objects.all()
                    data_res = {
                        "username": ftp_config[0].user_name,
                        "password": ftp_config[0].password,
                        "host": ftp_config[0].host,
                    }
                    return JsonResponse(data_res)
    data_res = {}
    return JsonResponse(data_res)

def savecf(request):
    if request.COOKIES.get("JESSIONID"):
        session_user = SessionStore(session_key=request.COOKIES.get("JESSIONID"))
        if check_session_timeout(session_user["timeout"]):
            checkuser = User.objects.filter(email=session_user["username"])
            if checkuser:
                if checkuser[0].email == "root.bootcamp.2020@gmail.com":
                    username = request.GET["username"]
                    password = request.GET["password"]
                    host = request.GET["host"]
                    save_config = FTP.objects.get(id=1)
                    save_config.user_name = username
                    save_config.password = password
                    save_config.host = host
                    save_config.schedule = 1
                    save_config.save()
                    message = {"message": "OK"}
                    return JsonResponse(message)
    data_res = {}
    return JsonResponse(data_res)


def show_key(request):
    if request.COOKIES.get("JESSIONID"):
        session_user = SessionStore(session_key=request.COOKIES.get("JESSIONID"))
        if check_session_timeout(session_user["timeout"]):
            checkuser = User.objects.filter(email=session_user["username"])
            if checkuser:
                if checkuser[0].email == "root.bootcamp.2020@gmail.com":
                    f = open("vul_web/Encrypt/aes_key.txt", "rb")
                    binaryData = f.read()
                    f.close()
                    # print(bytes.fromhex(binaryData.hex()))
                    data = {
                        "key": binaryData.hex()
                    }
                    return JsonResponse(data)
    data_res = {}
    return JsonResponse(data_res)
