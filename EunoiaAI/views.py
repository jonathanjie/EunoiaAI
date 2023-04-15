from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

from .config import expiry_time, docsearch, init_chat_and_memory
from .utils import save_convo_to_redis, restore_convo_from_redis
from .process_and_upload import process_and_upload
from django.utils.text import get_valid_filename
import os
import tempfile
import shutil

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'csv', 'zip', 'html', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def home(request):
    return render(request, 'index.html')

def upload_page(request):
    return render(request, 'upload-page.html')

@csrf_exempt
def chat(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode("utf-8"))

        if 'user_input' not in data or 'session_id' not in data:
            return JsonResponse({'error': 'user_input and session_id are required'}, status=400)

        user_input = data['user_input']
        session_id = data['session_id']
        pinecone_api_key = data["pinecone_api_key"]
        pinecone_env = data["pinecone_env"]
        pinecone_index_name = data["pinecone_index_name"]

        query_reply = docsearch.similarity_search(
            user_input, include_metadata=True)
        data_1 = query_reply[0].page_content
        data_2 = query_reply[1].page_content
        data_3 = query_reply[2].page_content

        conversation, memory = init_chat_and_memory(
            context_data=(data_1, data_2, data_3))

        restore_convo_from_redis(request, memory, session_id)  # Updated

        response = conversation.predict(input=user_input)

        save_convo_to_redis(request, memory, session_id)  # Updated

        return JsonResponse({'response': response})
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def upload_file(request):
    if request.method == 'POST':
        file_type = request.POST.get("file_type")
        pinecone_api_key = request.POST.get("pinecone_api_key")
        pinecone_env = request.POST.get("pinecone_env")
        pinecone_index_name = request.POST.get("pinecone_index_name")

        if not all([file_type, pinecone_api_key, pinecone_env, pinecone_index_name]):
            return JsonResponse({"error": "Missing required inputs"}, status=400)

        if file_type in ["javascript_website"]:
            input_data = request.POST.get("urls")
        elif file_type in ["html_website"]:
            input_data = request.POST.get("url")
        else:
            if "file" not in request.FILES:
                return JsonResponse({"error": "Missing file input"}, status=400)

            file = request.FILES["file"]
            if file and allowed_file(file.name):
                filename = get_valid_filename(file.name)

                with tempfile.TemporaryDirectory() as temp_dir:
                    file_path = os.path.join(temp_dir, filename)
                    with open(file_path, 'wb+') as destination:
                        for chunk in file.chunks():
                            destination.write(chunk)

                    input_data = file_path
                    documents = process_and_upload(
                        input_data, file_type, pinecone_api_key, pinecone_env, pinecone_index_name
                    )

        if file_type in ["javascript_website", "html_website"]:
            documents = process_and_upload(
                input_data, file_type, pinecone_api_key, pinecone_env, pinecone_index_name        )

        return JsonResponse({"success": "Documents processed and uploaded"}, status=200)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

