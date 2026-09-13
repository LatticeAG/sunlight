"""Sunlight v1 — sign-at-creation provenance SDK and offline verifier.

Declared lineage, not truth: verification establishes signed declared
lineage; it cannot prove training actually occurred or that a producer's
claim is truthful.
"""

from .domains import B, D, RAW, hash_domain, signature_domain, signature_message
from .ed25519 import (
    ed25519_sign, ed25519_verify, private_key_from_seed, public_from_seed,
)
from .errors import ERROR_CODES, SunlightError, cli_exit_for, error_body
from .ids import ID_PREFIXES, is_valid_id, new_id, random_hex
from .jcs import jcs, jcs_str
from .strictjson import parse_strict_json, parse_strict_json_str
from .schema import (
    parse_bundle, parse_client_config, parse_command, parse_command_body,
    parse_deployment_config, parse_genesis, parse_head_body, parse_head_ref,
    parse_local_key_file, parse_public_key, parse_signed_head, parse_statement,
    parse_statement_body, parse_token_binding, parse_tree_manifest, parse_trust,
)
from .artifact import (
    enumerate_tree, hash_artifact, hash_file_bytes, manifest_artifact, stage_tree,
)
from .objects import (
    Signer, seed_signer, sign_command, sign_head, sign_receipt, sign_statement,
    verify_signed_object,
)
from .verify import verify
from .capture import capture, files_identical
from .keys import (
    generate_key, key_file_from_seed, load_key_file, write_key_file,
    write_public_key_file,
)
from .config import DEFAULT_CONFIG_PATH, load_config, resolve_registry
from .cache import Cache
from .transport import RegistryTransport
from .evidence import compute_evidence_ref

__version__ = "1.0.0"
