import re
from typing import Optional, List
from pydantic import BaseModel, validator, Field
from app.models.ioc import IOCType


class IOCValidator:
    """Enhanced IOC validation with strict patterns."""
    
    # Compiled regex patterns for performance
    IPV4_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    
    IPV6_PATTERN = re.compile(
        r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,7}:|'
        r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
        r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
        r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
        r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
        r':((:[0-9a-fA-F]{1,4}){1,7}|:)|'
        r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
        r'::(ffff(:0{1,4}){0,1}:){0,1}'
        r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
        r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|'
        r'([0-9a-fA-F]{1,4}:){1,4}:'
        r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
        r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
    )
    
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    URL_PATTERN = re.compile(
        r'^(https?|ftp):\/\/'
        r'(?:\S+(?::\S*)?@)?'
        r'(?:'
        r'(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])'
        r'(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}'
        r'(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|'
        r'(?:(?:[a-zA-Z0-9]-?)*[a-zA-Z0-9]+)'
        r'(?:\.(?:[a-zA-Z0-9]-?)*[a-zA-Z0-9]+)*'
        r'(?:\.[a-zA-Z]{2,}))'
        r'(?::\d{2,5})?'
        r'(?:\/\S*)?$'
    )
    
    MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
    SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
    SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
    
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    @classmethod
    def validate_ioc_value(cls, ioc_type: str, value: str) -> bool:
        """Validate IOC value against its type."""
        if not value or not isinstance(value, str):
            return False
        
        value = value.strip()
        
        if ioc_type == IOCType.IPV4:
            return bool(cls.IPV4_PATTERN.match(value))
        elif ioc_type == IOCType.IPV6:
            return bool(cls.IPV6_PATTERN.match(value))
        elif ioc_type == IOCType.DOMAIN:
            return bool(cls.DOMAIN_PATTERN.match(value)) and len(value) <= 253
        elif ioc_type == IOCType.URL:
            return bool(cls.URL_PATTERN.match(value)) and len(value) <= 2048
        elif ioc_type == IOCType.HASH_MD5:
            return bool(cls.MD5_PATTERN.match(value))
        elif ioc_type == IOCType.HASH_SHA1:
            return bool(cls.SHA1_PATTERN.match(value))
        elif ioc_type == IOCType.HASH_SHA256:
            return bool(cls.SHA256_PATTERN.match(value))
        elif ioc_type == IOCType.EMAIL:
            return bool(cls.EMAIL_PATTERN.match(value)) and len(value) <= 254
        else:
            return True  # Unknown type, allow with warning
    
    @classmethod
    def sanitize_value(cls, value: str) -> str:
        """Sanitize IOC value."""
        if not isinstance(value, str):
            return str(value)
        # Remove null bytes and control characters except newlines/tabs
        return re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', value).strip()


def validate_stix_id(stix_id: str, expected_type: Optional[str] = None) -> bool:
    """Validate STIX 2.1 ID format."""
    pattern = re.compile(r'^[a-z0-9-]+--[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')
    if not pattern.match(stix_id):
        return False
    if expected_type and not stix_id.startswith(expected_type):
        return False
    return True


# Pydantic validators for request models
def validate_ioc_request(value: str, ioc_type: str) -> str:
    """Pydantic validator for IOC values."""
    sanitized = IOCValidator.sanitize_value(value)
    if not IOCValidator.validate_ioc_value(ioc_type, sanitized):
        raise ValueError(f"Invalid {ioc_type} value: {sanitized}")
    return sanitized
