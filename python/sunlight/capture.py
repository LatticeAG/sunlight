"""Cooperative creation-hook capture (spec §4.2, §5).

State machine:
  NEW → STAGING → FINALIZED → HASHED → SIGNED → PUBLISHED
  NEW/STAGING/FINALIZED/HASHED → FAILED        (local.CaptureFailed)
  SIGNED → FAILED                             (local.PublishFailed)
  SIGNED → PUBLICATION_UNKNOWN → PUBLISHED|FAILED
  FAILED → STAGING only via an explicit new capture() call.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat as statmod

from .artifact import enumerate_tree, hash_file_bytes, manifest_artifact
from .domains import B
from .errors import SunlightError
from .fsutil import dir_fsync, write_file_exclusive
from .jcs import jcs
from .objects import Signer, sign_statement
from .schema import parse_statement_body, parse_tree_manifest
from .strictjson import parse_strict_json

STAGED_NAME = "staged"


def files_identical(a: str, b: str) -> bool:
    sa, sb = os.lstat(a), os.lstat(b)
    if not (statmod.S_ISREG(sa.st_mode) and statmod.S_ISREG(sb.st_mode)) or sa.st_size != sb.st_size:
        return False
    return hash_file_bytes(a)["digest"] == hash_file_bytes(b)["digest"]


def _read_all(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def capture(request: dict, produce, signer: Signer, journal=lambda event, detail=None: None):
    staging_parent = request["staging_parent"]
    publish_path = request["publish_path"]
    profile = request["profile"]
    template = request["template"]

    if not os.path.isdir(staging_parent) or os.path.islink(staging_parent):
        raise SunlightError("USAGE", cause=ValueError("staging_parent is not a directory"))
    if os.path.lexists(publish_path):
        raise SunlightError("OUTPUT_EXISTS")

    staging = os.path.join(staging_parent, f".sunlight-stage-{secrets.token_hex(8)}")

    try:
        os.mkdir(staging, 0o700)
    except OSError as e:
        journal("local.CaptureFailed")
        raise SunlightError("IO_ERROR", cause=e) from e
    journal("local.CaptureStarted")

    staged_path = os.path.join(staging, STAGED_NAME)
    cleanup = lambda: shutil.rmtree(staging, ignore_errors=True)

    # STAGING → FINALIZED
    try:
        if profile == "tree/1":
            os.mkdir(staged_path, 0o700)
        produce(staged_path)
        if profile == "tree/1":
            if not os.path.isdir(staged_path):
                raise SunlightError("IO_ERROR", cause=ValueError("producer did not create a directory"))
        elif not os.path.isfile(staged_path):
            raise SunlightError("IO_ERROR", cause=ValueError("producer did not create a file"))
    except Exception as e:
        journal("local.CaptureFailed")
        cleanup()
        raise e if isinstance(e, SunlightError) else SunlightError("IO_ERROR", cause=e)
    journal("local.BytesFinalized")

    # FINALIZED → HASHED
    publish_bytes = None
    try:
        if profile == "bytes/1":
            r = hash_file_bytes(staged_path)
            artifact = {"profile": profile, "digest": r["digest"], "bytes": r["bytes"]}
        elif profile == "jcs/1":
            if os.lstat(staged_path).st_size > 1024 * 1024:
                raise SunlightError("BODY_LIMIT")
            try:
                value = parse_strict_json(_read_all(staged_path))
            except Exception as e:
                raise SunlightError("SCHEMA_INVALID", cause=e) from e
            publish_bytes = jcs(value)
            artifact = {"profile": profile, "digest": B(publish_bytes), "bytes": len(publish_bytes)}
        else:
            rels = enumerate_tree(staged_path)
            files = [
                {"path": rel, **hash_file_bytes(os.path.join(staged_path, *rel.split("/")))}
                for rel in rels
            ]
            manifest = parse_tree_manifest({"v": "sunlight.tree/1", "files": files})
            artifact = manifest_artifact(manifest)
    except Exception as e:
        journal("local.CaptureFailed")
        cleanup()
        raise e if isinstance(e, SunlightError) else SunlightError("IO_ERROR", cause=e)
    journal("local.ArtifactHashed", {"digest": artifact["digest"]})

    # HASHED → SIGNED
    try:
        body = parse_statement_body({
            "v": template["v"],
            "id": template["id"],
            "ledger": template["ledger"],
            "signer": template["signer"],
            "claimed_at_ms": template["claimed_at_ms"],
            "capture": "creation_hook",
            "subject": {"kind": template["kind"], "artifact": artifact},
            "parents": template["parents"],
            "details": template["details"],
            "evidence": template["evidence"],
        })
        statement = sign_statement(body, signer)
        write_file_exclusive(os.path.join(staging, "statement.json"), jcs(statement))
    except Exception as e:
        journal("local.CaptureFailed")
        cleanup()
        raise e if isinstance(e, SunlightError) else SunlightError("IO_ERROR", cause=e)
    journal("local.StatementSigned", {"statement": statement["hash"]})

    # SIGNED → PUBLISHED
    try:
        if publish_bytes is not None:
            write_file_exclusive(publish_path, publish_bytes)
        else:
            os.rename(staged_path, publish_path)
        dir_fsync(os.path.dirname(publish_path) or ".")
    except Exception as e:
        if not os.path.lexists(publish_path):
            journal("local.PublishFailed")
            raise SunlightError("IO_ERROR", cause=e) from e
        journal("local.PublicationUncertain")
        try:
            if profile != "tree/1":
                expected = publish_bytes if publish_bytes is not None else _read_all(staged_path)
                if expected != _read_all(publish_path):
                    raise SunlightError("ARTIFACT_CHANGED")
            elif not os.path.isdir(publish_path):
                raise SunlightError("ARTIFACT_CHANGED")
            os.lstat(os.path.join(staging, "statement.json"))
            journal("local.PublicationRecovered")
            return {"published_path": publish_path, "statement": statement, "recorded": False}
        except Exception as e2:
            journal("local.PublishFailed")
            raise e2 if isinstance(e2, SunlightError) else SunlightError("IO_ERROR", cause=e2)

    journal("local.ArtifactPublished", {"path": publish_path})
    return {"published_path": publish_path, "statement": statement, "recorded": False}
