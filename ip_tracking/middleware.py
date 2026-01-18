from django.core.cache import cache
from django.http import HttpResponseForbidden
from ipgeolocation import IpGeolocationAPI
from django.utils.timezone import now

from .models import RequestLog, BlockedIP


class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.geo_api = IpGeolocationAPI()

    def __call__(self, request):
        ip = self.get_client_ip(request)

        # BLOCKED IP CHECK
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP has been blocked.")

        country, city = self.get_geolocation(ip)

        RequestLog.objects.create(
            ip_address=ip,
            path=request.path,
            country=country,
            city=city,
        )

        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")

    def get_geolocation(self, ip):
        cache_key = f"geo_{ip}"
        cached = cache.get(cache_key)

        if cached:
            return cached["country"], cached["city"]

        try:
            data = self.geo_api.get_geolocation(ip)
            country = data.get("country_name")
            city = data.get("city")
        except Exception:
            country = None
            city = None

        cache.set(
            cache_key,
            {"country": country, "city": city},
            60 * 60 * 24,  # 24 hours
        )

        return country, city
