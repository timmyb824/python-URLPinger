from prometheus_client import Counter, Gauge, Histogram


class MetricsHandler:
    def __init__(self):
        self.check_counter = Counter(
            "endpoint_checks_total",
            "Total number of checks performed on each endpoint",
            ["endpoint", "name", "type"],
        )
        self.success_counter = Counter(
            "endpoint_checks_success_total",
            "Total number of successful checks for each endpoint",
            ["endpoint", "name", "type"],
        )
        self.failure_counter = Counter(
            "endpoint_checks_failure_total",
            "Total number of failed checks for each endpoint",
            ["endpoint", "name", "type"],
        )
        self.ssl_error_counter = Counter(
            "endpoint_ssl_errors_total",
            "Total number of SSL-related errors for each endpoint",
            ["endpoint", "name", "type"],
        )
        self.uptime_gauge = Gauge(
            "endpoint_uptime_status",
            "Current uptime status of each endpoint",
            ["endpoint", "name", "type"],
        )
        self.ssl_expiry_days = Gauge(
            "endpoint_ssl_expiry_days",
            "Days until SSL certificate expires",
            ["endpoint", "name", "type"],
        )
        self.response_time_histogram = Histogram(
            "endpoint_response_time_seconds",
            "Histogram of response times for each endpoint",
            ["endpoint", "name", "type"],
        )

    def record_check(self, endpoint: str, name: str, type_: str):
        self.check_counter.labels(endpoint=endpoint, name=name, type=type_).inc()

    def record_success(
        self, endpoint: str, name: str, type_: str, response_time: float
    ):
        self.success_counter.labels(endpoint=endpoint, name=name, type=type_).inc()
        self.uptime_gauge.labels(endpoint=endpoint, name=name, type=type_).set(1)
        self.response_time_histogram.labels(
            endpoint=endpoint, name=name, type=type_
        ).observe(response_time)

    def record_failure(self, endpoint: str, name: str, type_: str):
        self.failure_counter.labels(endpoint=endpoint, name=name, type=type_).inc()
        self.uptime_gauge.labels(endpoint=endpoint, name=name, type=type_).set(0)

    def record_maintenance_mode(self, endpoint: str, name: str, type_: str):
        self.uptime_gauge.labels(endpoint=endpoint, name=name, type=type_).set(2)

    def record_ssl_error(self, endpoint: str, name: str, type_: str):
        """Record an SSL-specific error."""
        self.ssl_error_counter.labels(endpoint=endpoint, name=name, type=type_).inc()

    def record_ssl_expiry(
        self, endpoint: str, name: str, type_: str, days_until_expiry: float
    ):
        """Record SSL certificate expiry information."""
        self.ssl_expiry_days.labels(endpoint=endpoint, name=name, type=type_).set(
            days_until_expiry
        )
