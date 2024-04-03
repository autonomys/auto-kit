"""
Auto Identity Module

This module provides functionalities for managing digital identities within the Auto SDK, 
including key generation, Auto ID management, and Auto ID registration and verification.
"""

from substrateinterface import Keypair
from .key_management import generate_rsa_key_pair, generate_ed25519_key_pair, key_to_hex, load_private_key, load_public_key
from .certificate_management import create_csr, issue_certificate, self_issue_certificate, get_subject_common_name
from .registry import Registry
from .utils import der_encode_signature_algorithm_oid

__version__ = '0.1.1'

__all__ = [
    "generate_rsa_key_pair",
    "generate_ed25519_key_pair",
    "key_to_hex",
    "load_private_key",
    "load_public_key",
    "create_csr",
    "issue_certificate",
    "self_issue_certificate",
    "get_subject_common_name",
    "der_encode_signature_algorithm_oid",
    "Registry",
    "Keypair",
]
