"""
AgentLens WORM Storage Adapters
---------------------------------
Persistence layer for the tamper-evident audit log.

RBI MRM 2026: Minimum 5-year retention for BFSI entities;
              10 years for decommissioned models.
DPDP Act 2023 §8: Audit log must never contain raw PII — hashes only.

Adapters:
  LocalNDJSONAdapter       — append-only rotating daily file (dev / on-prem)
  S3ObjectLockAdapter      — AWS S3 Object Lock (WORM) in ap-south-1 (Mumbai)
  AzureImmutableBlobAdapter — Azure Immutable Blob Storage (Central India)
  MultiAdapter             — fan-out writes to multiple backends in parallel

Usage:
    from agentlens.storage import LocalNDJSONAdapter, MultiAdapter, S3ObjectLockAdapter

    adapter = LocalNDJSONAdapter(base_dir="/var/log/agentlens")
    audit_log = AuditLog(entity_name="MyBank", storage_adapter=adapter)
"""

import json
import os
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .audit_log import AuditEvent


class WORMStorageAdapter(ABC):
    """
    Abstract base for WORM (Write Once Read Many) storage adapters.
    Every `write()` call must be atomic and append-only.
    Implementations must never modify or delete existing records.
    """

    @abstractmethod
    def write(self, event: "AuditEvent") -> None:
        """Persist a single audit event. Must be thread-safe."""
        ...

    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """Return a dict describing storage health. Used in compliance reports."""
        ...


# ─────────────────────────────────────────────────────────────────────────────
# Local NDJSON — daily rotating append-only files
# ─────────────────────────────────────────────────────────────────────────────

class LocalNDJSONAdapter(WORMStorageAdapter):
    """
    Writes one audit event per line (NDJSON) to daily rotating files.

    Files are named: {base_dir}/{entity}/{YYYY-MM-DD}.ndjson
    Each file is opened in append mode — existing records are never touched.

    Suitable for:
      - On-premise BFSI deployments (air-gapped environments)
      - Development and testing
      - Feeding to a local SIEM agent (Filebeat, Fluentd)

    IMPORTANT: In production, mount base_dir on a WORM-capable filesystem
    (e.g. NetApp SnapLock, Hitachi HCP, or IBM Spectrum Archive) to satisfy
    the RBI MRM 2026 immutability requirement.
    """

    def __init__(self, base_dir: str = "~/.agentlens/audit_logs"):
        self.base_dir = Path(base_dir).expanduser()
        self._lock = threading.Lock()
        self._current_date: Optional[str] = None
        self._current_fh = None

    def _get_file_path(self, entity_name: str) -> Path:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        # Sanitise entity name for use as directory
        safe_entity = "".join(c if c.isalnum() or c in "-_" else "_" for c in entity_name)
        entity_dir = self.base_dir / safe_entity
        entity_dir.mkdir(parents=True, exist_ok=True)
        return entity_dir / f"{date_str}.ndjson"

    def write(self, event: "AuditEvent") -> None:
        with self._lock:
            path = self._get_file_path(event.agent_id.split(":")[0] if ":" in event.agent_id else "default")
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict(), default=str) + "\n")

    def health_check(self) -> Dict[str, Any]:
        return {
            "adapter": "LocalNDJSONAdapter",
            "base_dir": str(self.base_dir),
            "base_dir_exists": self.base_dir.exists(),
            "writable": os.access(self.base_dir, os.W_OK) if self.base_dir.exists() else False,
            "worm_enforcement": "filesystem-level (mount on WORM-capable FS for production)",
        }


# ─────────────────────────────────────────────────────────────────────────────
# S3 Object Lock — AWS Mumbai (ap-south-1)
# ─────────────────────────────────────────────────────────────────────────────

class S3ObjectLockAdapter(WORMStorageAdapter):
    """
    Writes each audit event as an individual object to S3 with Object Lock
    (COMPLIANCE mode) in ap-south-1 (Mumbai) for data residency compliance.

    Each event becomes: s3://{bucket}/{entity}/{YYYY/MM/DD}/{event_id}.json
    Object Lock COMPLIANCE mode prevents deletion or modification by anyone,
    including root — satisfying RBI MRM 2026 immutability requirements.

    Requires: pip install boto3
    Bucket must be created with Object Lock enabled (cannot be enabled later).

    Example:
        adapter = S3ObjectLockAdapter(
            bucket="mybank-agentlens-audit",
            region="ap-south-1",
            retention_years=7,   # RBI MRM: 5yr active + 2yr buffer
        )

    For dev/test against LocalStack, pass endpoint_url (e.g.
    "http://localhost:4566") plus dummy credentials.
    """

    def __init__(
        self,
        bucket: str,
        region: str = "ap-south-1",
        retention_years: int = 7,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        endpoint_url: Optional[str] = None,
    ):
        self.bucket = bucket
        self.region = region
        self.retention_years = retention_years
        self._lock = threading.Lock()
        self._client = None
        self._boto3_available = False
        self._init_kwargs = {
            "region_name": region,
        }
        if aws_access_key_id:
            self._init_kwargs["aws_access_key_id"] = aws_access_key_id
            self._init_kwargs["aws_secret_access_key"] = aws_secret_access_key
        if endpoint_url:
            # Points at a non-AWS S3-compatible endpoint (e.g. LocalStack for
            # dev/test, or a VPC endpoint in prod).
            self._init_kwargs["endpoint_url"] = endpoint_url

        try:
            import boto3
            self._boto3 = boto3
            self._boto3_available = True
        except ImportError:
            pass

    def _get_client(self):
        if self._client is None:
            if not self._boto3_available:
                raise RuntimeError(
                    "boto3 is not installed. Run: pip install boto3\n"
                    "S3ObjectLockAdapter requires boto3 to write to AWS S3."
                )
            self._client = self._boto3.client("s3", **self._init_kwargs)
        return self._client

    def _object_key(self, event: "AuditEvent") -> str:
        ts = datetime.now(timezone.utc)
        entity_safe = "".join(
            c if c.isalnum() or c in "-_" else "_"
            for c in (event.agent_id or "default")
        )
        return f"{entity_safe}/{ts.strftime('%Y/%m/%d')}/{event.event_id}.json"

    def _retain_until(self) -> str:
        from datetime import timedelta
        retain_until = datetime.now(timezone.utc).replace(
            year=datetime.now(timezone.utc).year + self.retention_years
        )
        return retain_until.strftime("%Y-%m-%dT%H:%M:%SZ")

    def write(self, event: "AuditEvent") -> None:
        with self._lock:
            client = self._get_client()
            body = json.dumps(event.to_dict(), default=str).encode("utf-8")
            client.put_object(
                Bucket=self.bucket,
                Key=self._object_key(event),
                Body=body,
                ContentType="application/json",
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=self._retain_until(),
            )

    def health_check(self) -> Dict[str, Any]:
        status = {"adapter": "S3ObjectLockAdapter", "bucket": self.bucket, "region": self.region}
        if not self._boto3_available:
            status["error"] = "boto3 not installed"
            return status
        try:
            client = self._get_client()
            client.head_bucket(Bucket=self.bucket)
            lock_config = client.get_object_lock_configuration(Bucket=self.bucket)
            status["bucket_exists"] = True
            status["object_lock_enabled"] = True
            status["object_lock_config"] = str(lock_config.get("ObjectLockConfiguration", {}))
        except Exception as e:
            status["error"] = str(e)
        return status


# ─────────────────────────────────────────────────────────────────────────────
# Azure Immutable Blob — Central India
# ─────────────────────────────────────────────────────────────────────────────

class AzureImmutableBlobAdapter(WORMStorageAdapter):
    """
    Writes each audit event as an immutable blob in Azure Blob Storage
    (Central India region) with time-based retention policy.

    Container must have an immutability policy set to LOCKED state.
    Once locked, blobs cannot be deleted or modified for the retention period.

    Requires: pip install azure-storage-blob

    Example:
        adapter = AzureImmutableBlobAdapter(
            connection_string="DefaultEndpointsProtocol=https;AccountName=...",
            container_name="agentlens-audit",
        )
    """

    def __init__(self, connection_string: str, container_name: str):
        self.connection_string = connection_string
        self.container_name = container_name
        self._lock = threading.Lock()
        self._client = None
        self._azure_available = False

        try:
            from azure.storage.blob import BlobServiceClient
            self._BlobServiceClient = BlobServiceClient
            self._azure_available = True
        except ImportError:
            pass

    def _get_container_client(self):
        if self._client is None:
            if not self._azure_available:
                raise RuntimeError(
                    "azure-storage-blob is not installed. "
                    "Run: pip install azure-storage-blob"
                )
            service = self._BlobServiceClient.from_connection_string(self.connection_string)
            self._client = service.get_container_client(self.container_name)
        return self._client

    def _blob_name(self, event: "AuditEvent") -> str:
        ts = datetime.now(timezone.utc)
        entity_safe = "".join(
            c if c.isalnum() or c in "-_" else "_"
            for c in (event.agent_id or "default")
        )
        return f"{entity_safe}/{ts.strftime('%Y/%m/%d')}/{event.event_id}.json"

    def write(self, event: "AuditEvent") -> None:
        with self._lock:
            container = self._get_container_client()
            body = json.dumps(event.to_dict(), default=str).encode("utf-8")
            container.upload_blob(
                name=self._blob_name(event),
                data=body,
                overwrite=False,  # never overwrite — WORM semantics
                content_settings=None,
            )

    def health_check(self) -> Dict[str, Any]:
        status = {"adapter": "AzureImmutableBlobAdapter", "container": self.container_name}
        if not self._azure_available:
            status["error"] = "azure-storage-blob not installed"
            return status
        try:
            container = self._get_container_client()
            props = container.get_container_properties()
            status["container_exists"] = True
            status["immutability_policy"] = str(props.get("immutability_policy", "not set"))
        except Exception as e:
            status["error"] = str(e)
        return status


# ─────────────────────────────────────────────────────────────────────────────
# MultiAdapter — fan-out to multiple backends
# ─────────────────────────────────────────────────────────────────────────────

class MultiAdapter(WORMStorageAdapter):
    """
    Writes each event to multiple backends in parallel.
    Useful for: local file (fast) + S3 Object Lock (durable).
    A failure in one adapter is logged but does not block others.

    Example:
        adapter = MultiAdapter([
            LocalNDJSONAdapter("/var/log/agentlens"),
            S3ObjectLockAdapter("mybank-audit", region="ap-south-1"),
        ])
    """

    def __init__(self, adapters: List[WORMStorageAdapter]):
        if not adapters:
            raise ValueError("MultiAdapter requires at least one adapter.")
        self.adapters = adapters
        self._errors: List[str] = []

    def write(self, event: "AuditEvent") -> None:
        threads = []
        errors: List[str] = []
        lock = threading.Lock()

        def _write(adapter: WORMStorageAdapter):
            try:
                adapter.write(event)
            except Exception as e:
                with lock:
                    errors.append(f"{type(adapter).__name__}: {e}")

        for adapter in self.adapters:
            t = threading.Thread(target=_write, args=(adapter,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=10)

        if errors:
            # Record errors but don't raise — primary audit chain must not be interrupted
            self._errors.extend(errors)

    def health_check(self) -> Dict[str, Any]:
        return {
            "adapter": "MultiAdapter",
            "backends": [a.health_check() for a in self.adapters],
            "recent_errors": self._errors[-10:],
        }
