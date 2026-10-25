"""
Structured Evidence Parser (`code/tools/structured_evidence_tool.py`)
Parses all 28 `.json` files, 26 `.log` files, and 1 `.txt` file in `dataset/evidence/`
into canonical `ResourceObservation` objects.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from schemas import ResourceObservation
from tools.identity_graph_tool import IdentityGraphResolver
from tools.sql_evidence_tool import SqlEvidenceIngestor


class StructuredEvidenceIngestor:
    """Parses JSON bundles, service exports, log streams, and text handover files."""

    _KV_RE = re.compile(r'([a-zA-Z0-9_]+)=(?:"([^"]*)"|([^\s"|]+))')
    _TRACE_RE = re.compile(r"\b(tr-(?:rp-)?\d+|rb-\d+-\d+)\b")
    _TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)")

    def __init__(
        self,
        identity_resolver: IdentityGraphResolver,
        sql_ingestor: SqlEvidenceIngestor,
    ) -> None:
        self.identity_resolver = identity_resolver
        self.sql_ingestor = sql_ingestor

    @staticmethod
    def _clean(val: Any) -> Optional[str]:
        if val is None:
            return None
        s = str(val).strip()
        if not s or s.lower() in {"null", "none", "", "no direct identifier"}:
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
        return self._clean(user_id)

    def parse_json_file(
        self,
        file_id: str,
        file_path: Path,
        captured_at: str,
    ) -> List[ResourceObservation]:
        """Dispatch JSON evidence file by top-level schema."""
        data = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
        if "snapshots" in data:
            return self._parse_snapshot_bundle(file_id, captured_at, data)
        if "service_exports" in data:
            return self._parse_service_resource_export(file_id, captured_at, data)
        if "records" in data and "collection" in data:
            return self._parse_single_collection_json(file_id, captured_at, data)
        if "records" in data:
            return self._parse_lookup_manifest_json(file_id, captured_at, data)
        return []

    def _parse_snapshot_bundle(
        self,
        file_id: str,
        file_captured_at: str,
        data: Dict[str, Any],
    ) -> List[ResourceObservation]:
        """Parse `records_assurance_snapshot_bundle` JSON files (`evidence_02`..`51`)."""
        results: List[ResourceObservation] = []
        for snap in data.get("snapshots", []):
            snap_ts = snap.get("captured_at") or data.get("exported_at") or file_captured_at
            store = snap.get("data_store", "")
            collection = snap.get("collection", "")
            records = snap.get("records", [])

            if collection == "operational_record_history":
                for rec in records:
                    obs = self._parse_lookup_record_entry(
                        file_id=file_id,
                        file_captured_at=file_captured_at,
                        rec=rec,
                        default_ts=snap_ts,
                    )
                    if obs is not None:
                        results.append(obs)
                continue

            for rec in records:
                obs = self.sql_ingestor._parse_collection_record(
                    file_id=file_id,
                    file_captured_at=file_captured_at,
                    observed_at=snap_ts,
                    system_id=store,
                    collection=collection,
                    rec=rec,
                    is_replica_only=False,
                    source_name=f"{store}.{collection}",
                )
                if obs is not None:
                    results.append(obs)
        return results

    def _parse_service_resource_export(
        self,
        file_id: str,
        file_captured_at: str,
        data: Dict[str, Any],
    ) -> List[ResourceObservation]:
        """Parse `service_resource_export_*.json` (`evidence_62`..`92`)."""
        results: List[ResourceObservation] = []
        exports = data.get("service_exports", {})

        # 1. account_service -> profile_lookups
        for item in exports.get("account_service", {}).get("profile_lookups", []):
            rid = item["resource_id"]
            obs_ts = item.get("observed_at") or file_captured_at
            status_code = int(item.get("status_code", 200))
            prof = item.get("profile") or {}
            email = self._clean(prof.get("email"))
            phone = self._clean(prof.get("phone"))
            ehash = self._clean(prof.get("email_hash"))
            name = self._clean(prof.get("full_name"))
            uid = self._resolve_uid(prof.get("customer_reference"), email, phone, ehash)
            is_present = status_code == 200 and prof is not None
            results.append(
                ResourceObservation(
                    file_id=file_id,
                    file_captured_at=file_captured_at,
                    observed_at=obs_ts,
                    system_id="account_service",
                    resource_id=rid,
                    data_category="USER_PROFILE",
                    state="PRESENT" if is_present else "ABSENT",
                    user_id=uid,
                    email=email,
                    phone=phone,
                    email_hash=ehash,
                    full_name=name,
                    has_exposed_pii=is_present,
                    source_table_or_collection="service_exports.account_service",
                )
            )

        # 2. analytics_platform -> profiles
        for item in exports.get("analytics_platform", {}).get("profiles", []):
            rid = item["resource_id"]
            obs_ts = item.get("observed_at") or file_captured_at
            raw_ref = self._clean(item.get("customer_reference"))
            email = self._clean(item.get("email"))
            phone = self._clean(item.get("phone"))
            ehash = self._clean(item.get("email_hash"))
            uid = self._resolve_uid(raw_ref, email, phone, ehash)
            has_pii = any(x is not None for x in (raw_ref, email, phone, ehash))
            results.append(
                ResourceObservation(
                    file_id=file_id,
                    file_captured_at=file_captured_at,
                    observed_at=obs_ts,
                    system_id="analytics_platform",
                    resource_id=rid,
                    data_category="ANALYTICS_PROFILE",
                    state="PRESENT" if has_pii else "ANONYMIZED",
                    user_id=uid,
                    email=email,
                    phone=phone,
                    email_hash=ehash,
                    has_exposed_pii=has_pii,
                    source_table_or_collection="service_exports.analytics_platform",
                )
            )

        # 3. backup_service -> restore_entries
        for item in exports.get("backup_service", {}).get("restore_entries", []):
            rid = item["resource_id"]
            obs_ts = item.get("observed_at") or file_captured_at
            raw_ref = self._clean(item.get("customer_reference"))
            email = self._clean(item.get("customer_email"))
            allowed = bool(item.get("restore_allowed", False))
            uid = self._resolve_uid(raw_ref, email, None, None)
            results.append(
                ResourceObservation(
                    file_id=file_id,
                    file_captured_at=file_captured_at,
                    observed_at=obs_ts,
                    system_id="backup_service",
                    resource_id=rid,
                    data_category="BACKUP_ARCHIVE",
                    state="ACTIVE" if allowed else "BLOCKED",
                    user_id=uid,
                    email=email,
                    has_exposed_pii=allowed,
                    source_table_or_collection="service_exports.backup_service",
                )
            )

        # 4. export_service -> exports
        for item in exports.get("export_service", {}).get("exports", []):
            rid = item["resource_id"]
            obs_ts = item.get("observed_at") or file_captured_at
            raw_ref = self._clean(item.get("customer_reference"))
            email = self._clean(item.get("owner_email"))
            phone = self._clean(item.get("owner_phone"))
            uid = self._resolve_uid(raw_ref, email, phone, None)
            results.append(
                ResourceObservation(
                    file_id=file_id,
                    file_captured_at=file_captured_at,
                    observed_at=obs_ts,
                    system_id="export_service",
                    resource_id=rid,
                    data_category="USER_EXPORT",
                    state="PRESENT",
                    user_id=uid,
                    email=email,
                    phone=phone,
                    has_exposed_pii=True,
                    source_table_or_collection="service_exports.export_service",
                )
            )

        # 5. integration_service -> connectors
        for item in exports.get("integration_service", {}).get("connectors", []):
            rid = item["resource_id"]
            obs_ts = item.get("observed_at") or file_captured_at
            raw_ref = self._clean(item.get("customer_reference"))
            email = self._clean(item.get("customer_email"))
            enabled = bool(item.get("enabled", False))
            uid = self._resolve_uid(raw_ref, email, None, None)
            results.append(
                ResourceObservation(
                    file_id=file_id,
                    file_captured_at=file_captured_at,
                    observed_at=obs_ts,
                    system_id="integration_service",
                    resource_id=rid,
                    data_category="DATA_FLOW",
                    state="ACTIVE" if enabled else "DISABLED",
                    user_id=uid,
                    email=email,
                    has_exposed_pii=enabled,
                    source_table_or_collection="service_exports.integration_service",
                )
            )

        # 6. search_service -> index_queries
        for item in exports.get("search_service", {}).get("index_queries", []):
            rid = item["resource_id"]
            obs_ts = item.get("observed_at") or file_captured_at
            hits = item.get("hits", {})
            total = int(hits.get("total", 0))
            docs = hits.get("documents", [])
            doc = docs[0] if docs else {}
            email = self._clean(doc.get("email") or item.get("query"))
            raw_ref = self._clean(doc.get("customer_reference"))
            uid = self._resolve_uid(raw_ref, email, None, None)
            results.append(
                ResourceObservation(
                    file_id=file_id,
                    file_captured_at=file_captured_at,
                    observed_at=obs_ts,
                    system_id="search_service",
                    resource_id=rid,
                    data_category="SEARCH_INDEX_ENTRY",
                    state="PRESENT" if total > 0 else "ABSENT",
                    user_id=uid,
                    email=email,
                    has_exposed_pii=(total > 0),
                    source_table_or_collection="service_exports.search_service",
                )
            )

        # 7. security_service -> audit_records
        for item in exports.get("security_service", {}).get("audit_records", []):
            rid = item["resource_id"]
            obs_ts = item.get("observed_at") or file_captured_at
            ref = self._clean(item.get("subject_reference"))
            uid = self._resolve_uid(ref, None, None, None)
            results.append(
                ResourceObservation(
                    file_id=file_id,
                    file_captured_at=file_captured_at,
                    observed_at=obs_ts,
                    system_id="security_service",
                    resource_id=rid,
                    data_category="SECURITY_AUDIT_LOG",
                    state="PRESENT",
                    user_id=uid,
                    has_exposed_pii=False,
                    source_table_or_collection="service_exports.security_service",
                )
            )

        # 8. support_platform -> tickets
        for item in exports.get("support_platform", {}).get("tickets", []):
            rid = item["resource_id"]
            obs_ts = item.get("observed_at") or file_captured_at
            raw_ref = self._clean(item.get("customer_reference"))
            name = self._clean(item.get("requester_name"))
            email = self._clean(item.get("requester_email"))
            phone = self._clean(item.get("requester_phone"))
            uid = self._resolve_uid(raw_ref, email, phone, None)
            has_pii = any(x is not None for x in (name, email, phone))
            results.append(
                ResourceObservation(
                    file_id=file_id,
                    file_captured_at=file_captured_at,
                    observed_at=obs_ts,
                    system_id="support_platform",
                    resource_id=rid,
                    data_category="SUPPORT_MESSAGE",
                    state="PRESENT" if has_pii else "REDACTED",
                    user_id=uid,
                    email=email,
                    phone=phone,
                    full_name=name,
                    has_exposed_pii=has_pii,
                    source_table_or_collection="service_exports.support_platform",
                )
            )

        return results

    def _parse_single_collection_json(
        self,
        file_id: str,
        file_captured_at: str,
        data: Dict[str, Any],
    ) -> List[ResourceObservation]:
        """Parse standalone collection JSON files (`evidence_56`, `evidence_59`)."""
        obs_ts = data.get("captured_at") or file_captured_at
        collection = data.get("collection", "")
        system_id = (
            "analytics_platform"
            if collection == "customer_analytics_reports"
            else "export_service"
        )
        results: List[ResourceObservation] = []
        for rec in data.get("records", []):
            obs = self.sql_ingestor._parse_collection_record(
                file_id=file_id,
                file_captured_at=file_captured_at,
                observed_at=obs_ts,
                system_id=system_id,
                collection=collection,
                rec=rec,
                is_replica_only=False,
                source_name=collection,
            )
            if obs is not None:
                results.append(obs)
        return results

    def _parse_lookup_manifest_json(
        self,
        file_id: str,
        file_captured_at: str,
        data: Dict[str, Any],
    ) -> List[ResourceObservation]:
        """Parse lookup manifest JSON files (`evidence_13`, `evidence_36`, `evidence_50`)."""
        default_ts = data.get("exported_at") or file_captured_at
        results: List[ResourceObservation] = []
        for rec in data.get("records", []):
            obs = self._parse_lookup_record_entry(
                file_id=file_id,
                file_captured_at=file_captured_at,
                rec=rec,
                default_ts=default_ts,
            )
            if obs is not None:
                results.append(obs)
        return results

    def _parse_lookup_record_entry(
        self,
        file_id: str,
        file_captured_at: str,
        rec: Dict[str, Any],
        default_ts: str,
    ) -> Optional[ResourceObservation]:
        """Convert a normalized lookup entry (`system`, `resource_id`, `record_type`, `result`, `subject_reference`)."""
        obs_ts = rec.get("recorded_at") or default_ts
        sys_id = str(rec.get("system", "")).strip()
        rid = str(rec.get("resource_id", "")).strip()
        rtype = str(rec.get("record_type", "")).strip()
        result_raw = str(rec.get("result", "")).strip().upper()
        ref = self._clean(rec.get("subject_reference") or rec.get("lookup_value"))
        if not sys_id or not rid:
            return None

        email = ref if (ref and "@" in ref) else None
        uid = self._resolve_uid(ref, email, None, None)

        state_map = {
            "FOUND": "PRESENT",
            "NOT_FOUND": "ABSENT",
            "IDENTIFIABLE": "PRESENT",
            "ANONYMIZED": "ANONYMIZED",
            "REDACTED": "REDACTED",
            "ACTIVE": "ACTIVE",
            "DISABLED": "DISABLED",
            "BLOCKED": "BLOCKED",
        }
        state = state_map.get(result_raw, result_raw)
        has_pii = result_raw in {"FOUND", "IDENTIFIABLE", "ACTIVE"} and rtype not in {
            "SECURITY_AUDIT_LOG",
            "LEGAL_HOLD_RECORD",
        }

        return ResourceObservation(
            file_id=file_id,
            file_captured_at=file_captured_at,
            observed_at=obs_ts,
            system_id=sys_id,
            resource_id=rid,
            data_category=rtype,
            state=state,
            user_id=uid,
            email=email,
            has_exposed_pii=has_pii,
            source_table_or_collection="lookup_manifest",
        )

    def parse_handover_txt(
        self,
        file_id: str,
        file_path: Path,
        captured_at: str,
    ) -> List[ResourceObservation]:
        """Parse `evidence_03` (`customer_account_handover_20261001.txt`)."""
        results: List[ResourceObservation] = []
        for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("- "):
                continue
            parts = [p.strip() for p in line[2:].split("|")]
            if len(parts) < 6:
                continue
            ts, sys_id, rid, rtype, res_str, ref = parts[:6]
            obs = self._parse_lookup_record_entry(
                file_id=file_id,
                file_captured_at=captured_at,
                rec={
                    "recorded_at": ts,
                    "system": sys_id,
                    "resource_id": rid,
                    "record_type": rtype,
                    "result": res_str,
                    "subject_reference": ref,
                },
                default_ts=captured_at,
            )
            if obs is not None:
                results.append(obs)
        return results

    def parse_log_file(
        self,
        file_id: str,
        file_path: Path,
        captured_at: str,
    ) -> List[ResourceObservation]:
        """
        Parse all `.log` formats (`service_readback_logs`, `central_observability_export`,
        `search_index_service`, `downstream_delivery_service`, `support_platform`) with
        two-pass `trace_id` correlation.
        """
        raw_lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        parsed_entries: List[Dict[str, str]] = []
        trace_context: Dict[str, Dict[str, str]] = {}

        for raw_line in raw_lines:
            line = raw_line.strip()
            if not line:
                continue

            entry: Dict[str, str] = {}
            m_ts = self._TS_RE.match(line)
            if m_ts:
                entry["timestamp"] = m_ts.group(1)

            # Check if JSON-line log (`evidence_06`, `evidence_34`)
            json_start = line.find("{")
            if json_start != -1 and line.endswith("}"):
                try:
                    jobj = json.loads(line[json_start:])
                    for k, v in jobj.items():
                        if v is not None:
                            entry[str(k)] = str(v)
                except Exception:
                    pass

            # Unescape `\"` for cloud_runtime_export logs (`evidence_25`, `evidence_53`)
            normalized_line = line.replace('\\"', '"')

            # Pipe-delimited format (`evidence_21`, `evidence_48`):
            # `TIMESTAMP | LEVEL | SERVICE | TRACE_ID | EVENT | kv...`
            if " | " in normalized_line and json_start == -1:
                p_parts = [p.strip() for p in normalized_line.split("|")]
                if len(p_parts) >= 5:
                    entry.setdefault("service", p_parts[2])
                    entry.setdefault("trace_id", p_parts[3])
                    entry.setdefault("event", p_parts[4])

            # Bracketed format (`evidence_16`, `evidence_44`):
            # `TIMESTAMP [LEVEL] [SERVICE] [TRACE_ID] EVENT: kv...`
            m_br = re.search(
                r"\[([A-Z]+)\]\s+\[([a-z0-9_]+)\]\s+\[([^\]]+)\]\s+([a-z0-9_]+):",
                normalized_line,
            )
            if m_br:
                entry.setdefault("service", m_br.group(2))
                entry.setdefault("trace_id", m_br.group(3))
                entry.setdefault("event", m_br.group(4))

            # Syslog format (`evidence_11`, `evidence_39`):
            # `TIMESTAMP <PRI>1 node-X SERVICE TRACE_ID - - kv...`
            m_sys = re.search(
                r"<\d+>1\s+\S+\s+([a-z0-9_]+)\s+(tr-\d+)\s+-\s+-",
                normalized_line,
            )
            if m_sys:
                entry.setdefault("service", m_sys.group(1))
                entry.setdefault("trace_id", m_sys.group(2))

            # Extract all `key=value` or `key="value"` pairs
            for m_kv in self._KV_RE.finditer(normalized_line):
                k = m_kv.group(1)
                v = m_kv.group(2) if m_kv.group(2) is not None else m_kv.group(3)
                if k == "message":
                    continue
                entry[k] = v

            if "function" in entry and "service" not in entry:
                entry["service"] = entry["function"]
            if "requestId" in entry and "trace_id" not in entry:
                entry["trace_id"] = entry["requestId"]

            m_tr = self._TRACE_RE.search(normalized_line)
            if m_tr and "trace_id" not in entry:
                entry["trace_id"] = m_tr.group(1)

            tr_id = entry.get("trace_id")
            if tr_id:
                ctx = trace_context.setdefault(tr_id, {})
                for key_field in (
                    "lookup_key",
                    "match_key",
                    "subject_key",
                    "subject_ref",
                    "owner_key",
                    "scan_key",
                    "correlation_key",
                    "customer_email",
                    "customer_reference",
                    "subject_reference",
                    "email",
                    "requester_email",
                ):
                    val = self._clean(entry.get(key_field))
                    if val:
                        ctx[key_field] = val

            parsed_entries.append(entry)

        # Second pass: build ResourceObservations from terminal/completion events
        observations: List[ResourceObservation] = []
        for entry in parsed_entries:
            ev = entry.get("event", "")
            if not ev:
                continue

            if ev == "record_lookup":
                obs = self._parse_lookup_record_entry(
                    file_id=file_id,
                    file_captured_at=captured_at,
                    rec={
                        "recorded_at": entry.get("timestamp", captured_at),
                        "system": entry.get("system", ""),
                        "resource_id": entry.get("resource_id", ""),
                        "record_type": entry.get("record_type", ""),
                        "result": entry.get("result", ""),
                        "subject_reference": entry.get("subject_reference", ""),
                    },
                    default_ts=captured_at,
                )
                if obs is not None:
                    observations.append(obs)
                continue

            rid = self._clean(entry.get("resource_id"))
            if not rid:
                continue

            tr_id = entry.get("trace_id", "")
            ctx = trace_context.get(tr_id, {})
            obs_ts = entry.get("timestamp") or captured_at

            # Collect any identifier from the entry or its correlated trace context
            ident_candidates = [
                self._clean(entry.get(k)) or self._clean(ctx.get(k))
                for k in (
                    "subject_reference",
                    "customer_reference",
                    "subject_ref",
                    "lookup_key",
                    "match_key",
                    "subject_key",
                    "owner_key",
                    "scan_key",
                    "correlation_key",
                    "matched_value",
                    "email",
                    "customer_email",
                    "requester_email",
                )
            ]
            ident = next((x for x in ident_candidates if x is not None), None)
            email = ident if (ident and "@" in ident) else None
            phone = ident if (ident and ident.startswith("+")) else None
            ehash = ident if (ident and len(ident) == 64 and all(c in "0123456789abcdef" for c in ident.lower())) else None
            uid = self._resolve_uid(ident, email, phone, ehash)

            if ev == "profile_lookup_completed":
                http_status = int(entry.get("http_status", "200"))
                rows = int(entry.get("rows", "1" if http_status == 200 else "0"))
                is_present = http_status == 200 and rows > 0
                observations.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=obs_ts,
                        system_id="account_service",
                        resource_id=rid,
                        data_category="USER_PROFILE",
                        state="PRESENT" if is_present else "ABSENT",
                        user_id=uid,
                        email=email,
                        has_exposed_pii=is_present,
                        source_table_or_collection=f"log.{ev}",
                    )
                )

            elif ev == "index_query_completed":
                res = entry.get("result", "hit").lower()
                is_hit = res == "hit"
                observations.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=obs_ts,
                        system_id="search_service",
                        resource_id=rid,
                        data_category="SEARCH_INDEX_ENTRY",
                        state="PRESENT" if is_hit else "ABSENT",
                        user_id=uid,
                        email=email,
                        has_exposed_pii=is_hit,
                        source_table_or_collection=f"log.{ev}",
                    )
                )

            elif ev in {"analytics_profile_read_completed", "analytics_profile_read", "analytics_identity_scan"}:
                direct_cnt = int(entry.get("direct_identifiers", "1" if ev == "analytics_identity_scan" else "0"))
                em_val = self._clean(entry.get("email")) or (email if ev == "analytics_identity_scan" else None)
                ph_val = self._clean(entry.get("phone"))
                eh_val = self._clean(entry.get("email_hash"))
                ref_val = self._clean(entry.get("customer_reference"))
                has_pii = direct_cnt > 0 or any(x is not None for x in (em_val, ph_val, eh_val, ref_val))
                observations.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=obs_ts,
                        system_id="analytics_platform",
                        resource_id=rid,
                        data_category="ANALYTICS_PROFILE",
                        state="PRESENT" if has_pii else "ANONYMIZED",
                        user_id=uid,
                        email=em_val,
                        phone=ph_val,
                        email_hash=eh_val,
                        has_exposed_pii=has_pii,
                        source_table_or_collection=f"log.{ev}",
                    )
                )

            elif ev == "contact_lookup_completed":
                # Secondary identifier in analytics_platform (`case_12`: `analytics_9914`)
                observations.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=obs_ts,
                        system_id="analytics_platform",
                        resource_id=rid,
                        data_category="SECONDARY_IDENTIFIER",
                        state="PRESENT",
                        user_id=uid,
                        email_hash=ehash,
                        has_exposed_pii=True,
                        source_table_or_collection=f"log.{ev}",
                    )
                )

            elif ev in {"support_ticket_read_completed", "message_read", "message_pii_scan"}:
                msg_txt = self._clean(entry.get("message_text"))
                req_em = self._clean(entry.get("requester_email"))
                req_nm = self._clean(entry.get("requester_name"))
                req_ph = self._clean(entry.get("requester_phone"))
                if ev == "message_pii_scan":
                    has_pii = True
                elif msg_txt == "[REDACTED]":
                    has_pii = False
                else:
                    has_pii = any(x is not None for x in (req_em, req_nm, req_ph))
                observations.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=obs_ts,
                        system_id="support_platform",
                        resource_id=rid,
                        data_category="SUPPORT_MESSAGE",
                        state="PRESENT" if has_pii else "REDACTED",
                        user_id=uid,
                        email=req_em or email,
                        phone=req_ph or phone,
                        full_name=req_nm,
                        has_exposed_pii=has_pii,
                        source_table_or_collection=f"log.{ev}",
                    )
                )

            elif ev in {"attachment_pii_scan", "contact_query_completed"}:
                observations.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=obs_ts,
                        system_id="support_platform",
                        resource_id=rid,
                        data_category="SUPPORT_ATTACHMENT",
                        state="PRESENT",
                        user_id=uid,
                        email=email,
                        phone=phone,
                        has_exposed_pii=True,
                        source_table_or_collection=f"log.{ev}",
                    )
                )

            elif ev in {"export_download_check_completed", "export_metadata_read_completed"}:
                avail = str(entry.get("available", "true")).lower() == "true"
                observations.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=obs_ts,
                        system_id="export_service",
                        resource_id=rid,
                        data_category="USER_EXPORT",
                        state="PRESENT" if avail else "ABSENT",
                        user_id=uid,
                        email=email,
                        has_exposed_pii=avail,
                        source_table_or_collection=f"log.{ev}",
                    )
                )

            elif ev in {"connector_config_read_completed", "connector_config_loaded", "connector_heartbeat"}:
                enabled = str(entry.get("enabled", "true")).lower() == "true"
                observations.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=obs_ts,
                        system_id="integration_service",
                        resource_id=rid,
                        data_category="DATA_FLOW",
                        state="ACTIVE" if enabled else "DISABLED",
                        user_id=uid,
                        email=email,
                        has_exposed_pii=enabled,
                        source_table_or_collection=f"log.{ev}",
                    )
                )

            elif ev in {
                "restore_policy_read_completed",
                "restore_authorization_completed",
                "restore_candidate_evaluated",
            }:
                if ev == "restore_policy_read_completed":
                    allowed = str(entry.get("restore_allowed", "false")).lower() == "true"
                elif ev == "restore_authorization_completed":
                    allowed = str(entry.get("decision", "deny")).lower() != "deny"
                else:
                    allowed = (
                        str(entry.get("eligible", "true")).lower() == "true"
                        and str(entry.get("deletion_block", "false")).lower() == "false"
                    )
                observations.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=obs_ts,
                        system_id="backup_service",
                        resource_id=rid,
                        data_category="BACKUP_ARCHIVE",
                        state="ACTIVE" if allowed else "BLOCKED",
                        user_id=uid,
                        email=email,
                        has_exposed_pii=allowed,
                        source_table_or_collection=f"log.{ev}",
                    )
                )

            elif ev == "audit_record_read_completed":
                observations.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=obs_ts,
                        system_id="security_service",
                        resource_id=rid,
                        data_category="SECURITY_AUDIT_LOG",
                        state="PRESENT",
                        user_id=uid,
                        has_exposed_pii=False,
                        source_table_or_collection=f"log.{ev}",
                    )
                )

            elif ev == "retained_order_loaded":
                observations.append(
                    ResourceObservation(
                        file_id=file_id,
                        file_captured_at=captured_at,
                        observed_at=obs_ts,
                        system_id="legal_service",
                        resource_id=rid,
                        data_category="LEGAL_HOLD_RECORD",
                        state="PRESENT",
                        user_id=uid,
                        has_exposed_pii=False,
                        source_table_or_collection=f"log.{ev}",
                    )
                )

        return observations