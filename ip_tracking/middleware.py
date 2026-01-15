from django.http import HttpResponseForbidden
from django.utils.timezone import now
from .models import RequestLog, BlockedIP


"""
class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)
        path = request.path

        RequestLog.objects.create(
            ip_address=ip_address,
            path=path
        )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')

"""

class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = request.META.get('REMOTE_ADDR')

        # 🔴 Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Your IP has been blocked.")

        # 📝 Log request
        RequestLog.objects.create(
            ip_address=ip_address,
            path=request.path,
            timestamp=now()
        )

        return self.get_response(request)
