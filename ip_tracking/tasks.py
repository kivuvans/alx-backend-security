from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count, Q

from .models import RequestLog, SuspiciousIP


@shared_task
def detect_suspicious_ips():
    """
    Flags IPs that:
    - Make more than 100 requests per hour
    - Access sensitive paths (/admin, /login)
    """

    one_hour_ago = timezone.now() - timedelta(hours=1)

    # 1. IPs with more than 100 requests in the last hour
    high_volume_ips = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago)
        .values("ip_address")
        .annotate(total=Count("id"))
        .filter(total__gt=100)
    )

    for entry in high_volume_ips:
        SuspiciousIP.objects.get_or_create(
            ip_address=entry["ip_address"],
            reason="Exceeded 100 requests per hour"
        )

    # 2. IPs accessing sensitive paths
    sensitive_ips = (
        RequestLog.objects
        .filter(
            timestamp__gte=one_hour_ago,
            path__iregex=r"^/(admin|login)"
        )
        .values("ip_address")
        .distinct()
    )

    for entry in sensitive_ips:
        SuspiciousIP.objects.get_or_create(
            ip_address=entry["ip_address"],
            reason="Accessed sensitive endpoint"
        )

    return "Anomaly detection completed"
