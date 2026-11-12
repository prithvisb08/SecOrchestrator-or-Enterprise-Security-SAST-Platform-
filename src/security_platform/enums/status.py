from enum import StrEnum


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    RESOLVED = "RESOLVED"
    FIXED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    IN_PROGRESS = "IN_PROGRESS"
    REOPENED = "REOPENED"


# Alias for backward compatibility
Status = FindingStatus
