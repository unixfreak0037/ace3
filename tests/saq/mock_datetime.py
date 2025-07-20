from datetime import datetime, timezone
import pytz

MOCK_NOW = datetime(2017, 11, 11, 7, 36, 1, 1, pytz.UTC)

class mock_datetime(datetime):
    def now(timezone=None):
        return MOCK_NOW.replace(tzinfo=timezone)

    def utcnow():
        return MOCK_NOW
