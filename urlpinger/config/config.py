from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Config:
    name: str
    url: str
    acceptable_status_codes: Optional[list[int]] = field(default_factory=lambda: [200])
    check_type: str = "http"
    retries: int = 0
    consecutive_failures: int = 0
    retry_interval_seconds: int = 5
    check_interval_seconds: int = 60
    maintenance: bool = False
    status: bool = True

    def __post_init__(self):
        # Validate check_type
        if self.check_type not in {"http", "ping"}:
            raise ValueError(
                f"Invalid check_type '{self.check_type}'. Must be 'http' or 'ping'."
            )

        # Validate retries and interval are non-negative
        if self.retries < 0:
            raise ValueError("Retries must be a non-negative integer.")
        if self.check_interval_seconds <= 0:
            raise ValueError("Check interval must be a positive integer.")
        if self.retry_interval_seconds <= 0:
            raise ValueError("Retry interval must be a positive integer.")

        # If no acceptable status codes are provided for HTTP checks, default to [200]
        if not self.acceptable_status_codes and self.check_type == "http":
            self.acceptable_status_codes = [200]
