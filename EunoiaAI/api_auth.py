from django.http import JsonResponse
from .models import APIKey

class APIAuth:
    def authenticate(request):
        api_key = request.META.get('HTTP_X_API_KEY')
        api_secret = request.META.get('HTTP_X_API_SECRET')

        if not api_key or not api_secret:
            return JsonResponse({'error': 'Missing API Key or API Secret'}, status=401)

        try:
            api_key_obj = APIKey.objects.get(api_key=api_key, api_secret=api_secret)
        except APIKey.DoesNotExist:
            return JsonResponse({'error': 'Invalid API Key or API Secret'}, status=401)

        return api_key_obj.organization