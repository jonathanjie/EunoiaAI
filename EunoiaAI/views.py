# Third-party library imports
import json
import os
import tempfile
import uuid
import string
import random
from urllib.parse import quote_plus, urlencode
import pinecone
from langchain.vectorstores import Pinecone
from langchain.embeddings.openai import OpenAIEmbeddings
from authlib.integrations.django_client import OAuth

# Django imports
from django.http import JsonResponse, HttpResponseRedirect
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.contrib.auth import login as auth_login
from django.contrib import messages
from django.utils.text import get_valid_filename, slugify
from django.urls import reverse
from django.conf import settings

# Local imports
from .decorators import auth0_login_required
from .forms import CreateOrganizationForm, CreateAgentForm
from .models import Agent, UserProfile, APIKey
from .process_and_upload import process_and_upload
from .utils import expiry_time, init_chat_and_memory, save_convo_to_redis, restore_convo_from_redis, get_convo_history_from_redis
from .api_auth import APIAuth

# Constants
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'csv', 'zip', 'html', 'txt'}

# Initialize Pinecone and the embedding function
pinecone.init(api_key=settings.PINECONE_API_KEY,
              environment=settings.PINECONE_API_ENV)
pinecone_index = pinecone.Index(settings.PINECONE_INDEX)
embedding = OpenAIEmbeddings(openai_api_key=settings.OPENAI_API_KEY)

# OAuth configuration
oauth = OAuth()

oauth.register(
    "auth0",
    client_id=settings.AUTH0_CLIENT_ID,
    client_secret=settings.AUTH0_CLIENT_SECRET,
    access_token_url=f"https://{settings.AUTH0_DOMAIN}/oauth/token",
    authorize_url=f"https://{settings.AUTH0_DOMAIN}/authorize",
    api_base_url=f"https://{settings.AUTH0_DOMAIN}/",
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f"https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration",
)

# Helper Functions


def allowed_file(filename):
    """
    Check if the provided filename has an allowed extension.

    :param filename: The name of the file.
    :return: True if the filename has an allowed extension, False otherwise.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Chat Views
def chat_page(request, agent_namespace):
    """
    Render the chat page view.

    :param request: The request object.
    :param agent_namespace: The namespace of the agent.
    :return: Rendered chat page.
    """
    agent = get_object_or_404(Agent, namespace=agent_namespace)
    return render(request, 'chat-page.html', {'agent': agent})


def get_conversation_history(request, agent_namespace, session_id):
    """
    Get the conversation history for the given session_id.

    :param request: The request object.
    :param agent_namespace: The namespace of the agent.
    :param session_id: The ID of the session.
    :return: JsonResponse containing the conversation history.
    """
    full_convo_history = get_convo_history_from_redis(
        request, agent_namespace, session_id)
    return JsonResponse({'conversation_history': full_convo_history})


@auth0_login_required
def upload_page(request, agent_namespace):
    """
    Render the upload page view.

    :param request: The request object.
    :param agent_namespace: The namespace of the agent.
    :return: Rendered upload page.
    """
    agent = get_object_or_404(Agent, namespace=agent_namespace)
    return render(request, 'upload-page.html', {'agent': agent})


@csrf_exempt
def send_message(request, agent_namespace):
    """
    Send a message to the agent.

    :param request: The request object.
    :param agent_namespace: The namespace of the agent.
    :return: JsonResponse containing the agent's response or an error message.
    """
    if request.method == 'POST':
        data = json.loads(request.body.decode("utf-8"))

        user_input = data.get('user_input')
        session_id = data.get('session_id')

        if user_input and session_id:
            agent = get_object_or_404(Agent, namespace=agent_namespace)
            print("AGENT:")
            print(agent)

            # Initialize Pinecone with the given namespace
            docsearch = Pinecone.from_existing_index(
                embedding=embedding, index_name=settings.PINECONE_INDEX)

            # Retrieve relevant data from vector store
            query_reply = docsearch.similarity_search(
                user_input, namespace=agent_namespace, include_metadata=True)
            # query_reply = docsearch.similarity_search(user_input, include_metadata=True)
            # Set data_1, data_2, and data_3 using list comprehension and min() function
            data_1, data_2, data_3 = [
                q.page_content for q in query_reply[:3]] + [""] * (3 - len(query_reply))
            data_2 = data_2 or data_1
            data_3 = data_3 or data_2

            # Initialize conversation and memory for the specific session
            conversation, memory = init_chat_and_memory(
                (data_1, data_2, data_3), agent.primer_prompt, agent.company_name, agent.agent_name)

            # Restore conversation from Redis
            restore_convo_from_redis(
                request, memory, agent_namespace, session_id)

            response = conversation.predict(input=user_input)

            print(response)

            # Save the conversation to Redis
            save_convo_to_redis(request, memory, agent_namespace, session_id)

            return JsonResponse({"response": response})
        else:
            return JsonResponse({"error": "user_input or session_id not provided."}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method."}, status=405)


@csrf_exempt
def upload_file(request, agent_namespace):
    """
    Upload a file to the agent.

    :param request: The request object.
    :param agent_namespace: The namespace of the agent.
    :return: JsonResponse indicating the success or failure of the upload.
    """
    if request.method == 'POST':
        file_type = request.POST.get("file_type")
        pinecone_api_key = settings.PINECONE_API_KEY
        pinecone_env = settings.PINECONE_API_ENV
        pinecone_index = settings.PINECONE_INDEX

        if not all([file_type]):
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
                        input_data, file_type, pinecone_api_key, pinecone_env, pinecone_index, agent_namespace
                    )

        if file_type in ["javascript_website", "html_website"]:
            documents = process_and_upload(
                input_data, file_type, pinecone_api_key, pinecone_env, pinecone_index, agent_namespace
            )

        return JsonResponse({"success": "Documents processed and uploaded"}, status=200)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)


def manage_keys(request):
    """
    Render the manage keys view.

    :param request: The request object.
    :return: Rendered manage keys page.
    """
    api_keys = APIKey.objects.filter(status="active")
    return render(request, 'manage-keys.html', {'api_keys': api_keys})


@csrf_exempt
@auth0_login_required
def create_key(request):
    """
    Create a new API key for the authenticated user.

    :param request: The request object.
    :return: JsonResponse with success message or error message with the corresponding status code.
    """
    if request.method == 'POST':

        # Generate a random key
        def random_string(length):
            characters = string.ascii_letters + string.digits
            return ''.join(random.choice(characters) for i in range(length))

        key = f'key_{random_string(15)}'

        user_profile = UserProfile.objects.get(user=request.user)
        organization = user_profile.organization
        new_api_key = APIKey(organization=organization, key=key)
        new_api_key.save()
        return JsonResponse({"success": "API key created successfully.", "key": key}, status=200)
    else:
        return JsonResponse({"error": "Invalid request method."}, status=405)


@csrf_exempt
@auth0_login_required
def delete_key(request, key):
    """
    Delete an existing API key for the authenticated user.

    :param request: The request object.
    :param key: The API key to be deleted.
    :return: JsonResponse with success message or error message with the corresponding status code.
    """
    if request.method == 'POST':
        try:
            api_key = APIKey.objects.get(key=key)
            api_key.delete()
            return JsonResponse({"success": "API key deleted successfully."}, status=200)
        except APIKey.DoesNotExist:
            return JsonResponse({"error": "API key not found."}, status=404)
    else:
        return JsonResponse({"error": "Invalid request method."}, status=405)

# External API Views


@csrf_exempt
def api_send_message(request, agent_namespace):
    """
    Process a message and return a response using the specified agent namespace.

    :param request: The request object.
    :param agent_namespace: The namespace for the agent used in the conversation.
    :return: JsonResponse with the response message or error message with the corresponding status code.
    """
    api_key = request.META.get("HTTP_API_KEY")

    if not api_key:
        return JsonResponse({"error": "API key not provided."}, status=401)

    try:
        organization = APIKey.objects.get(key=api_key).organization
    except APIKey.DoesNotExist:
        return JsonResponse({"error": "Invalid API key or secret."}, status=403)

    if request.method == 'POST':
        data = json.loads(request.body.decode("utf-8"))

        user_input = data.get('user_input')
        session_id = data.get('session_id')

        if user_input and session_id:
            agent = get_object_or_404(Agent, namespace=agent_namespace)

            # Initialize Pinecone with the given namespace
            docsearch = Pinecone.from_existing_index(
                embedding=embedding, index_name=settings.PINECONE_INDEX)

            # Retrieve relevant data from vector store
            query_reply = docsearch.similarity_search(
                user_input, namespace=agent_namespace, include_metadata=True)
            data_1, data_2, data_3 = [
                q.page_content for q in query_reply[:3]] + [""] * (3 - len(query_reply))
            data_2 = data_2 or data_1
            data_3 = data_3 or data_2

            # Initialize conversation and memory for the specific session
            conversation, memory = init_chat_and_memory(
                (data_1, data_2, data_3), agent.primer_prompt, agent.company_name, agent.agent_display_name)

            # Restore conversation from Redis
            restore_convo_from_redis(
                request, memory, agent_namespace, session_id)

            response = conversation.predict(input=user_input)

            # Save the conversation to Redis
            full_convo_history = save_convo_to_redis(
                request, memory, agent_namespace, session_id)

            return JsonResponse({"response": response, "full_convo_history": full_convo_history})
        else:
            return JsonResponse({"error": "user_input or session_id not provided."}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method."}, status=405)


@csrf_exempt
def api_upload_file(request, agent_namespace):
    """
    Upload a file to the specified agent namespace.

    :param request: The request object.
    :param agent_namespace: The namespace for the agent used to store the uploaded file.
    :return: JsonResponse with success message or error message with the corresponding status code.
    """
    organization = APIAuth.authenticate(request)
    if isinstance(organization, JsonResponse):
        return organization

    if request.method == 'POST':
        file_type = request.POST.get("file_type")
        pinecone_api_key = settings.PINECONE_API_KEY
        pinecone_env = settings.PINECONE_API_ENV
        pinecone_index = settings.PINECONE_INDEX

        if not all([file_type]):
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
                        input_data, file_type, pinecone_api_key, pinecone_env, pinecone_index, agent_namespace
                    )

        if file_type in ["javascript_website", "html_website"]:
            documents = process_and_upload(
                input_data, file_type, pinecone_api_key, pinecone_env, pinecone_index, agent_namespace
            )

        return JsonResponse({"success": "Documents processed and uploaded"}, status=200)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

# Auth0 Views


def index(request):
    """
    Render the index view.

    :param request: The request object.
    :return: Rendered index page.
    """
    return render(
        request,
        "index.html",
        context={
            "session": request.session.get("user"),
            "pretty": json.dumps(request.session.get("user"), indent=4),
        },
    )


@auth0_login_required
def dashboard(request):
    """
    Render the user dashboard.

    :param request: The request object.
    :return: Rendered dashboard page.
    """
    user_profile = get_object_or_404(UserProfile, user=request.user)
    organization = user_profile.organization
    is_owner = organization.owner == request.user

    if is_owner:
        user_profiles = UserProfile.objects.filter(organization=organization)
    else:
        user_profiles = None

    agents = Agent.objects.filter(organization=organization)

    context = {
        'is_owner': is_owner,
        'user_profiles': user_profiles,
        'agents': agents
    }
    return render(request, 'dashboard.html', context)


def login(request):
    """
    Initiate the login process using Auth0.

    :param request: The request object.
    :return: Redirect to the Auth0 login page.
    """
    return oauth.auth0.authorize_redirect(
        request, request.build_absolute_uri(reverse("callback"))
    )


def callback(request):
    """
    Handle the Auth0 callback after successful authentication.

    :param request: The request object.
    :return: Redirect to the index view.
    """
    token = oauth.auth0.authorize_access_token(request)
    resp = oauth.auth0.get("userinfo", token=token)
    user_info = resp.json()
    request.session["user"] = user_info

    user, created = User.objects.get_or_create(username=user_info["sub"])
    if created:
        user.email = user_info["email"]
        user.save()

    auth_login(request, user)

    return redirect(request.build_absolute_uri(reverse("index")))


def logout(request):
    """
    Log out the user and clear the session.

    :param request: The request object.
    :return: Redirect to the Auth0 logout endpoint.
    """
    request.session.clear()

    return redirect(
        f"https://{settings.AUTH0_DOMAIN}/v2/logout?"
        + urlencode(
            {
                "returnTo": request.build_absolute_uri(reverse("index")),
                "client_id": settings.AUTH0_CLIENT_ID,
            },
            quote_via=quote_plus,
        ),
    )

# Organization and user management views


@auth0_login_required
def manage_organization(request):
    """
    Render the manage organization view.

    :param request: The request object.
    :return: Rendered manage organization page.
    """
    user_profile = UserProfile.objects.filter(user_id=request.user.id).first()

    if user_profile and user_profile.organization:
        organization = user_profile.organization
        form = CreateOrganizationForm(instance=organization)
    else:
        organization = None
        form = CreateOrganizationForm()

    if request.method == 'POST':
        if organization:
            form = CreateOrganizationForm(request.POST, instance=organization)
        else:
            form = CreateOrganizationForm(request.POST)

        if form.is_valid():
            organization = form.save(commit=False)

            # Generate the unique slug
            slug = slugify(organization.name) + '-' + str(uuid.uuid4())[:5]
            organization.slug = slug

            if not organization.owner:
                organization.owner = request.user

            organization.save()

            if not user_profile:
                user_profile = UserProfile(
                    user=request.user, organization=organization)
                user_profile.save()

            # Replace 'dashboard' with the name of the view you want to redirect the user to
            return redirect('dashboard')

    context = {'form': form, 'organization': organization}
    return render(request, 'manage-organization.html', context)


@auth0_login_required
def manage_user(request, user_id):
    """
    Manage a user profile.

    :param request: The request object.
    :param user_id: The ID of the user to be managed.
    :return: Rendered manage user page.
    """
    user_profile = get_object_or_404(UserProfile, user__id=user_id)
    organization = user_profile.organization

    if organization.owner != request.user:
        messages.error(
            request, "You don't have permission to delete this user.")
        return HttpResponseRedirect(reverse('dashboard'))

    if request.method == 'POST':
        user_profile.user.delete()
        messages.success(request, 'User deleted successfully.')
        return HttpResponseRedirect(reverse('dashboard'))

    return render(request, 'manage-user.html', {'user_profile': user_profile})


@auth0_login_required
def invite_user(request):
    """
    Invite a new user to join the organization.

    :param request: The request object.
    :return: Rendered invite user page.
    """
    if request.method == 'POST':
        email = request.POST['email']
        # You'll need to implement the function to send an invitation via Auth0
        send_invitation(request.user, email)
        messages.success(request, 'Invitation sent successfully.')
        return redirect('dashboard')

    return render(request, 'invite_user.html')


@auth0_login_required
def manage_agent(request, agent_namespace=None):
    """
    Manage an agent using the specified namespace.

    :param request: The request object.
    :param agent_namespace: The namespace for the agent to be managed.
    :return: Rendered manage agent page.
    """
    if agent_namespace:
        agent = get_object_or_404(Agent, namespace=agent_namespace)
        form = CreateAgentForm(instance=agent)
    else:
        agent = None
        form = CreateAgentForm()

    if request.method == 'POST':
        if 'delete' in request.POST:
            pinecone_index.delete(delete_all=True, namespace=agent_namespace)
            agent.delete()
            messages.success(request, 'Agent deleted successfully.')
            return redirect('dashboard')
        else:
            if agent:
                form = CreateAgentForm(request.POST, instance=agent)
            else:
                form = CreateAgentForm(request.POST)

            if form.is_valid():
                agent = form.save(commit=False)
                user_profile = UserProfile.objects.get(user=request.user)
                agent.organization = user_profile.organization

                if not agent.namespace:
                    # Generate the unique, immutable namespace only if it doesn't exist
                    namespace = f"{user_profile.organization.slug}-{slugify(agent.name)}-{uuid.uuid4().hex[:5]}"
                    agent.namespace = namespace

                agent.agent_display_name = request.POST.get('agent_display_name', None)
                agent.company_name = request.POST.get('company_name', None)
                agent.primer_prompt = request.POST.get('primer_prompt', None)

                agent.save()

                messages.success(request, 'Agent updated successfully.')
                return redirect('dashboard')

    context = {'form': form, 'agent': agent}
    return render(request, 'manage-agent.html', context)

# Helper functions for sending invitations


def send_invitation(current_user, email):
    """
    Send an email invitation to a user.

    :param current_user: The user object for the invite
    :param email: the email to send to
    """
    # Get access token
    token_url = f'https://YOUR_AUTH0_DOMAIN/oauth/token'
    token_payload = {
        'client_id': 'YOUR_CLIENT_ID',
        'client_secret': 'YOUR_CLIENT_SECRET',
        'audience': f'https://YOUR_AUTH0_DOMAIN/api/v2/',
        'grant_type': 'client_credentials'
    }
    token_response = requests.post(token_url, data=token_payload)
    access_token = token_response.json()['access_token']

    # Create passwordless email invitation
    invite_url = f'https://YOUR_AUTH0_DOMAIN/api/v2/tickets/passwordless/start'
    headers = {'Authorization': f'Bearer {access_token}'}
    user_profile = UserProfile.objects.get(user=current_user)
    organization_id = user_profile.organization.id

    invite_payload = {
        'client_id': 'YOUR_CLIENT_ID',
        'email': email,
        'send': 'code',
        'authParams': {
            'scope': 'openid',
            'organization_id': organization_id
        }
    }
    invite_response = requests.post(
        invite_url, headers=headers, json=invite_payload)

    return invite_response
