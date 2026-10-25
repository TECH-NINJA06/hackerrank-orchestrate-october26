"""
In-Memory SQLite Evidence Parser (`code/tools/sql_evidence_tool.py`)
Parses all 24 `.sql` database captures under `dataset/evidence/databases/` into
canonical `ResourceObservation` objects and detects primary-vs-replica drift.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from schemas import ResourceObservation
from tools.identity_graph_tool import IdentityGraphResolver


class SqlEvidenceIngestor:
    """Executes `.sql` snapshot files in in-memory SQLite and extracts ResourceObservations."""

    def __init__(self, identity_resolver: IdentityGraphResolver) -> None:
        self.identity_resolver = identity_resolver
        self.scoped_systems_by_file: Dict[str, Set[str]] = {}

    @staticmethod
    def _clean_val(val: Any) -> Optional[str]:
        if val is None:
            return None
        s = str(val).strip()
        if not s or s.lower() in {"null", "none", ""}:
            return None
        return s

    def _resolve_uid(
        self,
        user_id: Optional[str],
        email: Optional[str],
        phone: Optional[str],
        email_hash: Optional[str],
    ) -> Optional[str]:
        for cand in (user_id, email, email_hash, phone):
            uid = self.identity_resolver.resolve_user_id(cand)
            if uid:
                return uid
        return self._clean_val(user_id)

    def parse_sql_file(
        self,
        file_id: str,
        file_path: Path,
        captured_at: str,
    ) -> List[ResourceObservation]:
        """Load a `.sql` file into `:memory:` SQLite and return all extracted observations."""
        sql_text = file_path.read_text(encoding="utf-8", errors="replace")
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        try:
            conn.executescript(sql_text)
            cur = conn.cursor()
            tables = {
                row[0]
                for row in cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }

            observations: List[ResourceObservation] = []

            # Record scoped systems if `snapshot_scope` exists
            if "snapshot_scope" in tables:
                scoped = {
                    row["origin_system"]
                    for row in cur.execute("SELECT origin_system FROM snapshot_scope").fetchall()
                }
                self.scoped_systems_by_file[file_id] = scoped

            # Topology 1: JSON-row tables (`customer_data_primary` + replica tables)
            json_tables = [
                t
                for t in sorted(tables)
                if t.startswith("customer_data_")
            ]
            if json_tables:
                observations.extend(
                    self._parse_json_replica_tables(cur, file_id, captured_at, json_tables)
                )

            # Topology 2: Account failover replica (`evidence_54`)
            if "customer_profiles_failover_replica" in tables or "customer_profiles_primary" in tables:
                observations.extend(
                    self._parse_account_failover_tables(cur, file_id, captured_at, tables)
                )

            # Topology 3: Search primary (`evidence_57`)
            if "search_documents_primary" in tables:
                observations.extend(
                    self._parse_search_primary_table(cur, file_id, captured_at)
                )

            # Topology 4: Normalized inventory tables (`evidence_63`..`93`)
            if "customer_profiles" in tables:
                observations.extend(
                    self._parse_inventory_tables(cur, file_id, captured_at, tables)
                )

            return observations
        finally:
            conn.close()

    def _parse_json_replica_tables(
        self,
        cur: sqlite3.Cursor,
        file_id: str,
        captured_at: str,
        json_tables: List[str],
    ) -> List[ResourceObservation]:
        """
        Merge `customer_data_primary` and any replica tables. If a resource exists in any replica
        table (even if deleted from primary), it is still PRESENT in the system.
        """
        primary_rids: Set[str] = set()
        if "customer_data_primary" in json_tables:
            primary_rids = {
                r["resource_id"]
                for r in cur.execute("SELECT resource_id FROM customer_data_primary").fetchall()
            }

        merged_rows: Dict[str, Tuple[sqlite3.Row, str]] = {}
        for tname in json_tables:
            for row in cur.execute(f"SELECT * FROM {tname}").fetchall():
                rid = row["resource_id"]
                if rid not in merged_rows or tname != "customer_data_primary":
                    merged_rows[rid] = (row, tname)

        results: List[ResourceObservation] = []
        for rid, (row, tname) in merged_rows.items():
            origin_system = row["origin_system"]
            collection = row["collection_name"]
            updated_at = row["updated_at"] or captured_at
            rec = json.loads(row["record_json"])
            is_replica_only = bool(primary_rids and rid not in primary_rids)

            obs = self._parse_collection_record(
                file_id=file_id,
                file_captured_at=captured_at,
                observed_at=updated_at,
                system_id=origin_system,
                collection=collection,
                rec=rec,
                is_replica_only=is_replica_only,
                source_name=tname,
            )
            if obs is not None:
                results.append(obs)
        return results

    def _parse_collection_record(
        self,
        file_id: str,
        file_captured_at: str,
        observed_at: str,
        system_id: str,
        collection: str,
        rec: Dict[str, Any],
        is_replica_only: bool,
        source_name: str,
    ) -> Optional[ResourceObservation]:
        """Convert a collection JSON object into a standardized ResourceObservation."""
        rid = str(rec.get("resource_id", "")).strip()
        if not rid:
            return None

        if collection == "customer_profiles":
            email = self._clean_val(rec.get("email"))
            phone = self._clean_val(rec.get("phone"))
            ehash = self._clean_val(rec.get("email_hash"))
            name = self._clean_val(rec.get("full_name"))
            uid = self._resolve_uid(rec.get("customer_reference") or rec.get("user_id"), email, phone, ehash)
            return ResourceObservation(
                file_id=file_id,
                file_captured_at=file_captured_at,
                observed_at=observed_at,
                system_id="account_service",
                resource_id=rid,
                data_category="USER_PROFILE",
                state="PRESENT",
                user_id=uid,
                email=email,
                phone=phone,
                email_hash=ehash,
                full_name=name,
                has_exposed_pii=True,
                is_replica_only=is_replica_only,
                source_table_or_collection=source_name,
                raw_metadata=rec,
            )

        if collection == "customer_search_documents":
            doc = rec.get("document", rec)
            email = self._clean_val(doc.get("email"))
            phone = self._clean_val(doc.get("phone"))
            ehash = self._clean_val(doc.get("email_hash"))
            name = self._clean_val(doc.get("display_name"))
            uid = self._resolve_uid(doc.get("customer_reference"), email, phone, ehash)
            return ResourceObservation(
                file_id=file_id,
                file_captured_at=file_captured_at,
                observed_at=observed_at,
                system_id="search_service",
                resource_id=rid,
                data_category="SEARCH_INDEX_ENTRY",
                state="PRESENT",
                user_id=uid,
                email=email,
                phone=phone,
                email_hash=ehash,
                full_name=name,
                has_exposed_pii=True,
                is_replica_only=is_replica_only,
                source_table_or_collection=source_name,
                raw_metadata=rec,
            )

        if collection == "customer_analytics_reports":
            email = self._clean_val(rec.get("email"))
            phone = self._clean_val(rec.get("phone"))
            ehash = self._clean_val(rec.get("email_hash"))
            raw_uid = self._clean_val(rec.get("user_id") or rec.get("customer_reference"))
            uid = self._resolve_uid(raw_uid, email, phone, ehash)
            has_pii = any(x is not None for x in (raw_uid, email, phone, ehash))
            return ResourceObservation(
                file_id=file_id,
                file_captured_at=file_captured_at,
                observed_at=observed_at,
                system_id="analytics_platform",
                resource_id=rid,
                data_category="ANALYTICS_PROFILE",
                state="PRESENT" if has_pii else "ANONYMIZED",
                user_id=uid,
                email=email,
                phone=phone,
                email_hash=ehash,
                has_exposed_pii=has_pii,
                is_replica_only=is_replica_only,
                source_table_or_collection=source_name,
                raw_metadata=rec,
            )

        if collection == "support_conversations":
            msg = str(rec.get("message_text", "")).strip()
            raw_uid = self._clean_val(rec.get("subject_reference") or rec.get("customer_reference"))
            is_redacted = msg == "[REDACTED]"
            # Extract email from message_text if present
            found_email = None
            if not is_redacted:
                for token in msg.replace(",", " ").split():
                    cleaned = token.strip(".;:()[]\"'")
                    if "@" in cleaned:
                        found_email = cleaned
                        break
            uid = self._resolve_uid(raw_uid, found_email, None, None)
            return ResourceObservation(
                file_id=file_id,
                file_captured_at=file_captured_at,
                observed_at=observed_at,
                system_id="support_platform",
                resource_id=rid,
                data_category="SUPPORT_MESSAGE",
                state="REDACTED" if is_redacted else "PRESENT",
                user_id=uid,
                email=found_email,
                has_exposed_pii=not is_redacted,
                is_replica_only=is_replica_only,
                source_table_or_collection=source_name,
                raw_metadata=rec,
            )

        if collection == "ticket_attachments":
            email = self._clean_val(rec.get("uploaded_by"))
            uid = self._resolve_uid(rec.get("subject_reference"), email, None, None)
            return ResourceObservation(
                file_id=file_id,
                file_captured_at=file_captured_at,
                observed_at=observed_at,
                system_id="support_platform",
                resource_id=rid,
                data_category="SUPPORT_ATTACHMENT",
                state="PRESENT",
                user_id=uid,
                email=email,
                has_exposed_pii=True,
                is_replica_only=is_replica_only,
                source_table_or_collection=source_name,
                raw_metadata=rec,
            )

        if collection == "customer_export_jobs":
            email = self._clean_val(rec.get("owner_email"))
            phone = self._clean_val(rec.get("owner_phone"))
            avail = bool(rec.get("download_available", True))
            uid = self._resolve_uid(rec.get("customer_reference"), email, phone, None)
            return ResourceObservation(
                file_id=file_id,
                file_captured_at=file_captured_at,
                observed_at=observed_at,
                system_id="export_service",
                resource_id=rid,
                data_category="USER_EXPORT",
                state="PRESENT" if avail else "ABSENT",
                user_id=uid,
                email=email,
                phone=phone,
                has_exposed_pii=avail,
                is_replica_only=is_replica_only,
                source_table_or_collection=source_name,
                raw_metadata=rec,
            )

        if collection == "connector_configurations":
            sel = self._clean_val(rec.get("subject_selector") or rec.get("customer_email") or rec.get("customer_reference"))
            enabled = bool(rec.get("enabled", False))
            uid = self._resolve_uid(sel, sel if (sel and "@" in sel) else None, None, None)
            return ResourceObservation(
                file_id=file_id,
                file_captured_at=file_captured_at,
                observed_at=observed_at,
                system_id="integration_service",
                resource_id=rid,
                data_category="DATA_FLOW",
                state="ACTIVE" if enabled else "DISABLED",
                user_id=uid,
                email=sel if (sel and "@" in sel) else None,
                has_exposed_pii=enabled,
                is_replica_only=is_replica_only,
                source_table_or_collection=source_name,
                raw_metadata=rec,
            )

        if collection == "backup_catalog":
            ref = self._clean_val(rec.get("subject_reference") or rec.get("customer_email"))
            allowed = bool(rec.get("restore_allowed", False))
            uid = self._resolve_uid(ref, ref if (ref and "@" in ref) else None, None, None)
            return ResourceObservation(
                file_id=file_id,
                file_captured_at=file_captured_at,
                observed_at=observed_at,
                system_id="backup_service",
                resource_id=rid,
                data_category="BACKUP_ARCHIVE",
                state="ACTIVE" if allowed else "BLOCKED",
                user_id=uid,
                email=ref if (ref and "@" in ref) else None,
                has_exposed_pii=allowed,
                is_replica_only=is_replica_only,
                source_table_or_collection=source_name,
                raw_metadata=rec,
            )

        if collection == "security_audit_events":
            ref = self._clean_val(rec.get("subject_reference"))
            uid = self._resolve_uid(ref, None, None, None)
            return ResourceObservation(
                file_id=file_id,
                file_captured_at=file_captured_at,
                observed_at=observed_at,
                system_id="security_service",
                resource_id=rid,
                data_category="SECURITY_AUDIT_LOG",
                state="PRESENT",
                user_id=uid,
                has_exposed_pii=False,
                is_replica_only=is_replica_only,
                source_table_or_collection=source_name,
                raw_metadata=rec,
            )

        if collection == "retained_order_records":
            ref = self._clean_val(rec.get("subject_reference"))
            uid = self._resolve_uid(ref, None, None, None)
            return ResourceObservation(
                file_id=file_id,
                file_captured_at=file_captured_at,
                observed_at=observed_at,
                system_id="legal_service",
                resource_id=rid,
                data_category="LEGAL_HOLD_RECORD",
                state="PRESENT",
                user_id=uid,
                has_exposed_pii=False,
                is_replica_only=is_replica_only,
                source_table_or_collection=source_name,
                raw_metadata=rec,
            )

        if collection == "deleted_customer_references":
            ref = self._clean_val(rec.get("subject_reference"))
            name = self._clean_val(rec.get("name"))
            email = self._clean_val(rec.get("email"))
            phone = self._clean_val(rec.get("phone"))
            ehash = self._clean_val(rec.get("email_hash"))
            uid = self._resolve_uid(ref, email, phone, ehash)
            has_pii = any(x is not None for x in (name, email, phone, ehash))
            return ResourceObservation(
                file_id=file_id,
                file_captured_at=file_captured_at,
                observed_at=observed_at,
                system_id="identity_service",
                resource_id=rid,
                data_category="ACCOUNT_TOMBSTONE",
                state="PRESENT" if has_pii else "REDACTED",
                user_id=uid,
                email=email,
                phone=phone,
                email_hash=ehash,
                full_name=name,
                has_exposed_pii=has_pii,
                is_replica_only=is_replica_only,
                source_table_or_collection=source_name,
                raw_metadata=rec,
            )

        return None

    def _parse_account_failover_tables(
        self,
        cur: sqlite3.Cursor,
        file_id: str,
        captured_at: str,
        tables: Set[str],
    ) -> List[ResourceObservation]:
        """Parse `evidence_54` (`customer_profiles_failover_replica` vs `customer_profiles_primary`)."""
        self.scoped_systems_by_file.setdefault(file_id, set()).add("account_service")
        primary_rids: Set[str] = set()
        if "customer_profiles_primary" in tables:
            primary_rids = {
                r["resource_id"]
                for r in cur.execute("SELECT resource_id FROM customer_profiles_primary").fetchall()
            }

        merged: Dict[str, Tuple[sqlite3.Row, str]] = {}
        for tname in ("customer_profiles_primary", "customer_profiles_failover_replica"):
            if tname in tables:
                for row in cur.execute(f"SELECT * FROM {tname}").fetchall():
                    merged[row["resource_id"]] = (row, tname)

        results: List[ResourceObservation] = []
        for rid, (row, tname) in merged.items():
            email = self._clean_val(row["email"])
            phone = self._clean_val(row["phone"])
            name = self._clean_val(row["full_name"])
            uid = self._resolve_uid(row["user_id"], email, phone, None)
            results.append(
                ResourceObservation(
                    file_id=file_id,
                    file_captured_at=captured_at,
                    observed_at=row["updated_at"] or captured_at,
                    system_id="account_service",
                    resource_id=rid,
                    data_category="USER_PROFILE",
                    state="PRESENT",
                    user_id=uid,
                    email=email,
                    phone=phone,
                    full_name=name,
                    has_exposed_pii=True,
                    is_replica_only=(rid not in primary_rids),
                    source_table_or_collection=tname,
                )
            )
        return results

    def _parse_search_primary_table(
        self,
        cur: sqlite3.Cursor,
        file_id: str,
        captured_at: str,
    ) -> List[ResourceObservation]:
        """Parse `evidence_57` (`search_documents_primary`)."""
        self.scoped_systems_by_file.setdefault(file_id, set()).add("search_service")
        results: List[ResourceObservation] = []
        for row in cur.execute("SELECT * FROM search_documents_primary").fetchall():
            rid = row["resource_id"]
            email = self._clean_val(row["email"])
            name = self._clean_val(row["display_name"])
            uid = self._resolve_uid(None, email, None, None)
            results.append(
                ResourceObservation(
                    file_id=file_id,
                    file_captured_at=captured_at,
                    observed_at=row["indexed_at"] or captured_at,
                    system_id="search_service",
                    resource_id=rid,
                    data_category="SEARCH_INDEX_ENTRY",
                    state="PRESENT",
                    user_id=uid,
                    email=email,
                    full_name=name,
                    has_exposed_pii=True,
                    source_table_or_collection="search_documents_primary",
                    raw_metadata={"source_resource_id": row["source_resource_id"]},
                )
            )
        return results

    def _parse_inventory_tables(
        self,
        cur: sqlite3.Cursor,
        file_id: str,
        captured_at: str,
        tables: Set[str],
    ) -> List[ResourceObservation]:
        """Parse the 8 relational inventory tables in `customer_data_inventory_*.sql` (`evidence_63`..`93`)."""
        results: List[ResourceObservation] = []

        if "customer_profiles" in tables:
            for r in cur.execute("SELECT * FROM customer_profiles").fetchall():
                email = self._clean_val(r["email"])
                phone = self._clean_val(r["phone"])
                ehash = self._clean_val(r["email_hash"])
                name = self._clean_val(r["full_name"])
                uid = self._resolve_uid(r["customer_reference"], email, phone, ehash)
                results.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=r["updated_at"] or captured_at,
                        system_id="account_service",
                        resource_id=r["resource_id"],
                        data_category="USER_PROFILE",
                        state="PRESENT",
                        user_id=uid,
                        email=email,
                        phone=phone,
                        email_hash=ehash,
                        full_name=name,
                        has_exposed_pii=True,
                        source_table_or_collection="customer_profiles",
                    )
                )

        if "customer_search_documents" in tables:
            for r in cur.execute("SELECT * FROM customer_search_documents").fetchall():
                email = self._clean_val(r["email"])
                phone = self._clean_val(r["phone"])
                ehash = self._clean_val(r["email_hash"])
                name = self._clean_val(r["display_name"])
                uid = self._resolve_uid(r["customer_reference"], email, phone, ehash)
                results.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=r["updated_at"] or captured_at,
                        system_id="search_service",
                        resource_id=r["resource_id"],
                        data_category="SEARCH_INDEX_ENTRY",
                        state="PRESENT",
                        user_id=uid,
                        email=email,
                        phone=phone,
                        email_hash=ehash,
                        full_name=name,
                        has_exposed_pii=True,
                        source_table_or_collection="customer_search_documents",
                    )
                )

        if "customer_analytics_profiles" in tables:
            for r in cur.execute("SELECT * FROM customer_analytics_profiles").fetchall():
                raw_ref = self._clean_val(r["customer_reference"])
                email = self._clean_val(r["email"])
                phone = self._clean_val(r["phone"])
                ehash = self._clean_val(r["email_hash"])
                uid = self._resolve_uid(raw_ref, email, phone, ehash)
                has_pii = any(x is not None for x in (raw_ref, email, phone, ehash))
                results.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=r["updated_at"] or captured_at,
                        system_id="analytics_platform",
                        resource_id=r["resource_id"],
                        data_category="ANALYTICS_PROFILE",
                        state="PRESENT" if has_pii else "ANONYMIZED",
                        user_id=uid,
                        email=email,
                        phone=phone,
                        email_hash=ehash,
                        has_exposed_pii=has_pii,
                        source_table_or_collection="customer_analytics_profiles",
                    )
                )

        if "support_records" in tables:
            for r in cur.execute("SELECT * FROM support_records").fetchall():
                raw_ref = self._clean_val(r["customer_reference"])
                name = self._clean_val(r["requester_name"])
                email = self._clean_val(r["requester_email"])
                phone = self._clean_val(r["requester_phone"])
                uid = self._resolve_uid(raw_ref, email, phone, None)
                has_pii = any(x is not None for x in (name, email, phone))
                results.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=r["updated_at"] or captured_at,
                        system_id="support_platform",
                        resource_id=r["resource_id"],
                        data_category="SUPPORT_MESSAGE",
                        state="PRESENT" if has_pii else "REDACTED",
                        user_id=uid,
                        email=email,
                        phone=phone,
                        full_name=name,
                        has_exposed_pii=has_pii,
                        source_table_or_collection="support_records",
                    )
                )

        if "customer_exports" in tables:
            for r in cur.execute("SELECT * FROM customer_exports").fetchall():
                raw_ref = self._clean_val(r["customer_reference"])
                email = self._clean_val(r["owner_email"])
                phone = self._clean_val(r["owner_phone"])
                uid = self._resolve_uid(raw_ref, email, phone, None)
                results.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=r["updated_at"] or captured_at,
                        system_id="export_service",
                        resource_id=r["resource_id"],
                        data_category="USER_EXPORT",
                        state="PRESENT",
                        user_id=uid,
                        email=email,
                        phone=phone,
                        has_exposed_pii=True,
                        source_table_or_collection="customer_exports",
                    )
                )

        if "connector_subscriptions" in tables:
            for r in cur.execute("SELECT * FROM connector_subscriptions").fetchall():
                raw_ref = self._clean_val(r["customer_reference"])
                email = self._clean_val(r["customer_email"])
                enabled = bool(int(r["enabled"]))
                uid = self._resolve_uid(raw_ref, email, None, None)
                results.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=r["updated_at"] or captured_at,
                        system_id="integration_service",
                        resource_id=r["resource_id"],
                        data_category="DATA_FLOW",
                        state="ACTIVE" if enabled else "DISABLED",
                        user_id=uid,
                        email=email,
                        has_exposed_pii=enabled,
                        source_table_or_collection="connector_subscriptions",
                    )
                )

        if "backup_restore_entries" in tables:
            for r in cur.execute("SELECT * FROM backup_restore_entries").fetchall():
                raw_ref = self._clean_val(r["customer_reference"])
                email = self._clean_val(r["customer_email"])
                allowed = bool(int(r["restore_allowed"]))
                uid = self._resolve_uid(raw_ref, email, None, None)
                results.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=r["updated_at"] or captured_at,
                        system_id="backup_service",
                        resource_id=r["resource_id"],
                        data_category="BACKUP_ARCHIVE",
                        state="ACTIVE" if allowed else "BLOCKED",
                        user_id=uid,
                        email=email,
                        has_exposed_pii=allowed,
                        source_table_or_collection="backup_restore_entries",
                    )
                )

        if "security_audit_records" in tables:
            for r in cur.execute("SELECT * FROM security_audit_records").fetchall():
                ref = self._clean_val(r["subject_reference"])
                uid = self._resolve_uid(ref, None, None, None)
                results.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=r["updated_at"] or captured_at,
                        system_id="security_service",
                        resource_id=r["resource_id"],
                        data_category="SECURITY_AUDIT_LOG",
                        state="PRESENT",
                        user_id=uid,
                        has_exposed_pii=False,
                        source_table_or_collection="security_audit_records",
                    )
                )

        return results