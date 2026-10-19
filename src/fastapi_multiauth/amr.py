"""Authentication Method Reference values (RFC 8176) for ``amr`` claims."""

from enum import StrEnum


class AuthenticationMethodReference(StrEnum):
    """The registered values of the ``amr`` claim (RFC 8176 §2, IANA registry).

    A ``StrEnum``, so members compare equal to the strings a provider puts in
    the claim: ``AuthenticationMethodReference.MULTI_FACTOR in claims["amr"]``.
    """

    FACE = "face"
    """Biometric authentication using facial recognition."""
    FINGERPRINT = "fpt"
    """Biometric authentication using a fingerprint."""
    GEOLOCATION = "geo"
    """Use of geolocation information for authentication."""
    HARDWARE_KEY = "hwk"
    """Proof-of-possession of a hardware-secured key."""
    IRIS = "iris"
    """Biometric authentication using an iris scan."""
    KNOWLEDGE_BASED = "kba"
    """Knowledge-based authentication."""
    MULTI_CHANNEL = "mca"
    """Multiple-channel authentication."""
    MULTI_FACTOR = "mfa"
    """Multiple-factor authentication."""
    ONE_TIME_PASSWORD = "otp"  # noqa: S105
    """One-time password."""
    PIN = "pin"
    """Personal Identification Number or pattern used to unlock a device."""
    PROOF_OF_POSSESSION = "pop"
    """Proof-of-possession of a key (OpenID Connect EAP ACR Values 1.0)."""
    PASSWORD = "pwd"  # noqa: S105
    """Password-based authentication."""
    RISK_BASED = "rba"
    """Risk-based authentication."""
    RETINA = "retina"
    """Biometric authentication using a retina scan."""
    SMART_CARD = "sc"
    """Smart card."""
    SMS = "sms"
    """Confirmation by an SMS text message to a registered number."""
    SOFTWARE_KEY = "swk"
    """Proof-of-possession of a software-secured key."""
    TELEPHONE = "tel"
    """Confirmation by a telephone call to a registered number."""
    USER_PRESENCE = "user"
    """User presence test."""
    VOICE = "vbm"
    """Biometric authentication using a voiceprint."""
    WINDOWS_INTEGRATED = "wia"
    """Windows integrated authentication."""
