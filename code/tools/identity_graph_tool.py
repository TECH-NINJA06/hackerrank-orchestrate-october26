"""
Deterministic Transitive Identity Graph Resolver (`code/tools/identity_graph_tool.py`)
Resolves current and historical identifiers (user_id, email, phone, email_hash, name, linked resources)
from `user_identities.csv`, `user_audit_log.csv`, and `system_activity.csv` up to `audit_at`.
"""

from __future__ import annotations

import csv
import hashlib
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from schemas import ActivityEvent, IdentityCluster


class IdentityGraphResolver:
    """
    Builds a bidirectional identity index over `user_identities.csv`, `user_audit_log.csv`,
    and `LINK_RESOURCE_IDENTITY` / `CLASSIFY_REQUEST` events in `system_activity.csv`.
    """

    _LINK_RE = re.compile(
        r"linked\s+(?P<rid>[a-z0-9_]+)\s+\((?P<label>[^)]+)\)\s+to\s+(?P<email>[^\s]+)\s+and\s+(?P<uid>user_\d+)",
        re.IGNORECASE,
    )
    _ATTACH_LINK_RE = re.compile(
        r"confirmed\s+(?P<rid>[a-z0-9_]+)\s+\((?P<label>[^)]+)\)\s+belongs\s+only\s+to\s+(?P<email>[^\s]+)\s+and\s+(?P<uid>user_\d+)",
        re.IGNORECASE,
    )
    _CLASSIFY_NON_DEL_RE = re.compile(
        r"classified\s+request\s+for\s+(?P<rid>account_\d+)\s+as\s+non-deletion",
        re.IGNORECASE,
    )

    def __init__(self, dataset_dir: Path) -> None:
        self.dataset_dir = dataset_dir
        self.users_by_id: Dict[str, Dict[str, str]] = {}
        self.audit_rows_by_uid: Dict[str, List[Dict[str, str]]] = {}
        self.email_to_uid: Dict[str, str] = {}
        self.hash_to_uid: Dict[str, str] = {}
        self.phone_to_uid: Dict[str, str] = {}
        self.catalog_links_by_uid: Dict[str, List[Tuple[str, str, str, str]]] = {}
        self.non_deletion_accounts: Set[str] = set()

        self._load_user_identities()
        self._load_user_audit_log()
        self._load_activity_identity_links()

    @staticmethod
    def sha256_hex(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest().lower()

    @staticmethod
    def normalize_phone(phone: str) -> str:
        return "".join(ch for ch in phone if ch.isdigit() or ch == "+")

    def _load_user_identities(self) -> None:
        path = self.dataset_dir / "user_identities.csv"
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                email_raw = row["email"].strip()
                email_low = email_raw.lower()
                phone_raw = row["phone"].strip()
                ehash = row["email_hash"].strip().lower()

                self.users_by_id[uid] = row
                self.email_to_uid[email_low] = uid
                self.hash_to_uid[ehash] = uid
                self.hash_to_uid[self.sha256_hex(email_low)] = uid
                self.hash_to_uid[self.sha256_hex(email_raw)] = uid
                self.phone_to_uid[self.normalize_phone(phone_raw)] = uid

    def _load_user_audit_log(self) -> None:
        path = self.dataset_dir / "user_audit_log.csv"
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                self.audit_rows_by_uid.setdefault(uid, []).append(row)
                field_name = row["field_name"].strip()
                for col in ("old_value", "new_value"):
                    val = (row.get(col) or "").strip()
                    if not val:
                        continue
                    if field_name == "email":
                        low = val.lower()
                        self.email_to_uid[low] = uid
                        self.hash_to_uid[self.sha256_hex(low)] = uid
                        self.hash_to_uid[self.sha256_hex(val)] = uid
                    elif field_name == "email_hash":
                        self.hash_to_uid[val.lower()] = uid
                    elif field_name == "phone":
                        self.phone_to_uid[self.normalize_phone(val)] = uid

        for uid in self.audit_rows_by_uid:
            self.audit_rows_by_uid[uid].sort(key=lambda r: (r["event_time"], r["audit_id"]))

    def _load_activity_identity_links(self) -> None:
        path = self.dataset_dir / "system_activity.csv"
        if not path.exists():
            return
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                etype = row["event_type"].strip()
                details = row["details"].strip()
                ev_time = row["event_time"].strip()
                target_sys = row["target_system"].strip()
                rid = row["resource_id"].strip()

                if etype == "LINK_RESOURCE_IDENTITY":
                    m = self._LINK_RE.search(details) or self._ATTACH_LINK_RE.search(details)
                    if m:
                        uid = m.group("uid").strip()
                        email = m.group("email").strip().rstrip(".;,")
                        self.email_to_uid[email.lower()] = uid
                        self.catalog_links_by_uid.setdefault(uid, []).append(
                            (ev_time, rid, target_sys, email)
                        )
                elif etype == "CLASSIFY_REQUEST":
                    m = self._CLASSIFY_NON_DEL_RE.search(details)
                    if m:
                        self.non_deletion_accounts.add(m.group("rid").strip())

    def resolve_user_id(self, identifier: Optional[str]) -> Optional[str]:
        """Resolve any email, email_hash, user_id, or phone to its canonical `user_id`."""
        if not identifier:
            return None
        val = str(identifier).strip()
        if not val or val.lower() in {"null", "none", "no direct identifier"}:
            return None
        low = val.lower()
        if low.startswith("user_") and low in self.users_by_id:
            return low
        if low in self.email_to_uid:
            return self.email_to_uid[low]
        if low in self.hash_to_uid:
            return self.hash_to_uid[low]
        norm_p = self.normalize_phone(val)
        if norm_p and norm_p in self.phone_to_uid:
            return self.phone_to_uid[norm_p]
        return None

    def resolve_cluster(self, seed_email: str, audit_at: str) -> IdentityCluster:
        """
        Build the complete transitive IdentityCluster for `seed_email` using all records
        available at or before `audit_at`.
        """
        email_clean = seed_email.strip()
        email_low = email_clean.lower()
        uid = self.resolve_user_id(email_low)
        if uid is None:
            uid = f"unresolved_{self.sha256_hex(email_low)[:8]}"

        cluster = IdentityCluster(user_id=uid)
        cluster.emails.add(email_low)
        cluster.raw_emails.add(email_clean)
        cluster.email_hashes.add(self.sha256_hex(email_low))
        cluster.email_hashes.add(self.sha256_hex(email_clean))

        if uid in self.users_by_id:
            u_row = self.users_by_id[uid]
            name = u_row["name"].strip()
            u_email = u_row["email"].strip()
            u_phone = u_row["phone"].strip()
            u_hash = u_row["email_hash"].strip().lower()

            cluster.primary_name = name
            cluster.names.add(name)
            cluster.emails.add(u_email.lower())
            cluster.raw_emails.add(u_email)
            cluster.phones.add(u_phone)
            cluster.email_hashes.add(u_hash)
            cluster.email_hashes.add(self.sha256_hex(u_email.lower()))
            cluster.email_hashes.add(self.sha256_hex(u_email))

        for a_row in self.audit_rows_by_uid.get(uid, []):
            if a_row["event_time"].strip() <= audit_at:
                cluster.audit_ids.append(a_row["audit_id"].strip())
            field_name = a_row["field_name"].strip()
            for col in ("old_value", "new_value"):
                val = (a_row.get(col) or "").strip()
                if not val:
                    continue
                if field_name == "email":
                    cluster.emails.add(val.lower())
                    cluster.raw_emails.add(val)
                    cluster.email_hashes.add(self.sha256_hex(val.lower()))
                    cluster.email_hashes.add(self.sha256_hex(val))
                elif field_name == "email_hash":
                    cluster.email_hashes.add(val.lower())
                elif field_name == "phone":
                    cluster.phones.add(val)
                elif field_name == "name":
                    cluster.names.add(val)

        for ev_time, rid, target_sys, linked_email in self.catalog_links_by_uid.get(uid, []):
            if ev_time <= audit_at:
                cluster.linked_resources[rid] = target_sys
                cluster.emails.add(linked_email.lower())
                cluster.raw_emails.add(linked_email)
                cluster.email_hashes.add(self.sha256_hex(linked_email.lower()))

        return cluster