from django.shortcuts import render
from django.http import HttpResponse
from django.http import JsonResponse
from django.shortcuts import render
import pickle
import base64
from django.contrib import messages
from vul_web.models import *
from vul_web.rce.post import *
def homePageView(request):
    if request.method == 'GET':
        page2_query = "select * from vul_web_infopost where tag ='page2'"
        page_query_ex = InfoPost.objects.raw(page2_query)
        data_page2 ={"page_data": page_query_ex}
        return render(request, 'index.html',data_page2)
def getInfoPost(request):

    if request.method == 'GET':
        data_res = {}
        name_post = request.GET.get("name_post")
        bl = ['"']
        if name_post.find('"') !=-1:
            data_res["message"] = "attack detected"
            return JsonResponse(data_res)
        query_string = 'select * from vul_web_infopost where tag="'+name_post+'"'
        querydata = InfoPost.objects.raw(query_string)
        for item in querydata:
            print(item.author)
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
    return  JsonResponse(data_res)

def sPost(request):
    return render(request, 'contact.html')
def sPost_process_new_post(request):
    if request.method == "POST":
        image = request.FILES['filename']
        image_name = image.name
        print("++++++++++++")
        print(request.POST.get('name'))
        print(request.POST.get('phone'))
        print(request.POST.get('email'))
        print(request.POST.get('message'))
        new_post = POST(
            request.POST.get('name'),
            request.POST.get('phone'),
            request.POST.get('email'),
            request.POST.get('message'),
            image_name
        )
        save_note(new_post,image)
        file_name_hash = new_post.internal_title
        message_ = "Đã gửi bài viết thành công, mã bài viết: "+str(file_name_hash)
        messages.success(request,message_)

    return render(request, 'contact.html')
def show_post_detail(request):
