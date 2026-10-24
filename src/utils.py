from datetime import datetime, timezone


def now_utc() -> datetime:
    """Return the current datetime in UTC timezone."""
    return datetime.now(timezone.utc)


def iso_utc(dt: datetime) -> str:
    """Format a datetime object as ISO 8601 string in UTC with milliseconds and 'Z'."""
    return dt.astimezone(timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def parse_date(value: str | None) -> datetime | None:
    """Parse an ISO 8601 date string to an aware UTC datetime object."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None
