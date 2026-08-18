class PolicyValidationError(ValueError):
    """Raised when a security policy is ambiguous or malformed.

    Security configuration is parsed strictly so common typos cannot silently
    weaken enforcement.
    """
