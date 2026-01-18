from django.shortcuts import render

# Create your views here.
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from django.contrib.auth import authenticate, login


@csrf_exempt
@ratelimit(key='ip', rate='5/m', method='POST', block=False)
@ratelimit(key='ip', rate='10/m', method='POST', block=False)
def login_view(request):
    """
    Rate limits:
    - Anonymous users: 5 requests/min
    - Authenticated users: 10 requests/min
    """

    if getattr(request, 'limited', False):
        return JsonResponse(
            {"error": "Too many requests. Please slow down."},
            status=429
        )

    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    username = request.POST.get("username")
    password = request.POST.get("password")

    user = authenticate(request, username=username, password=password)
    if user:
        login(request, user)
        return JsonResponse({"message": "Login successful"})

    return JsonResponse({"error": "Invalid credentials"}, status=401)
