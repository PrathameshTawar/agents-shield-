"""Authentication, identity verification, and human review approval token management."""

import hashlib
import hmac
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from fastapi import Header, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from shield.core.config import settings
from shield.core.models import PendingApproval, ToolCallRequest, UserIdentity

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _compute_args_digest(arguments: Dict[str, Any]) -> str:
    """Computes a deterministic hash of arguments to bind approval tokens to specific parameters."""
    import json
    try:
        serialized = json.dumps(arguments, sort_keys=True, default=str)
    except Exception:
        serialized = str(sorted(arguments.items()))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


class ApprovalStore:
    """Thread-safe store for pending human review actions and single-use approval tokens."""

    def __init__(self):
        self._lock = threading.Lock()
        self._approvals: Dict[str, PendingApproval] = {}
        self._tokens: Dict[str, str] = {}  # token -> approval_id

    def create_approval(
        self,
        request: ToolCallRequest,
        ttl_seconds: Optional[int] = None,
    ) -> PendingApproval:
        ttl = ttl_seconds or settings.APPROVAL_EXPIRY_SECONDS
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl)

        approval = PendingApproval(
            tool_name=request.tool_name,
            user_id=request.user_id,
            user_role=request.user_role,
            tenant_id=request.tenant_id,
            arguments=request.arguments,
            status="pending",
            created_at=now,
            expires_at=expires_at,
        )

        with self._lock:
            self._approvals[approval.approval_id] = approval

        return approval

    def get_approval(self, approval_id: str) -> Optional[PendingApproval]:
        with self._lock:
            approval = self._approvals.get(approval_id)
            if not approval:
                return None
            if datetime.now(timezone.utc) > approval.expires_at and approval.status == "pending":
                approval.status = "expired"
            return approval

    def approve(
        self,
        approval_id: str,
        reviewer_identity: UserIdentity,
    ) -> Tuple[bool, Optional[str], str]:
        """Approves a pending request and issues a single-use signed approval token."""
        if reviewer_identity.user_role not in ["admin", "security_officer"]:
            return False, None, f"Reviewer role '{reviewer_identity.user_role}' lacks authority to grant approvals"

        with self._lock:
            approval = self._approvals.get(approval_id)
            if not approval:
                return False, None, "Approval request not found"

            now = datetime.now(timezone.utc)
            if now > approval.expires_at:
                approval.status = "expired"
                return False, None, "Approval request has expired"

            if approval.status != "pending":
                return False, None, f"Cannot approve request with status '{approval.status}'"

            # Generate single-use signed token bound to this approval
            token_entropy = secrets.token_urlsafe(32)
            args_hash = _compute_args_digest(approval.arguments)
            signature = hmac.new(
                settings.APPROVAL_SECRET.encode("utf-8"),
                f"{approval.approval_id}:{approval.tool_name}:{args_hash}:{token_entropy}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            approval_token = f"appr_{token_entropy}_{signature[:24]}"
            approval.status = "approved"
            approval.approval_token = approval_token
            self._tokens[approval_token] = approval.approval_id

            return True, approval_token, "Approval granted successfully"

    def reject(
        self,
        approval_id: str,
        reviewer_identity: UserIdentity,
        reason: str = "Rejected by human reviewer",
    ) -> Tuple[bool, str]:
        """Rejects a pending approval request."""
        if reviewer_identity.user_role not in ["admin", "security_officer"]:
            return False, f"Reviewer role '{reviewer_identity.user_role}' lacks authority to reject approvals"

        with self._lock:
            approval = self._approvals.get(approval_id)
            if not approval:
                return False, "Approval request not found"

            if approval.status != "pending":
                return False, f"Cannot reject request with status '{approval.status}'"

            approval.status = "rejected"
            return True, "Approval rejected"

    def validate_and_consume_token(
        self,
        token: str,
        request: ToolCallRequest,
    ) -> Tuple[bool, str]:
        """Validates that a provided token is genuine, matches the request parameters, hasn't expired, and burns it."""
        with self._lock:
            approval_id = self._tokens.get(token)
            if not approval_id:
                return False, "Invalid or unrecognized approval token"

            approval = self._approvals.get(approval_id)
            if not approval:
                return False, "Approval record associated with token not found"

            if approval.status == "used":
                return False, "Approval token has already been consumed (replay attack detected)"

            if approval.status != "approved":
                return False, f"Approval token is invalid for request status '{approval.status}'"

            now = datetime.now(timezone.utc)
            if now > approval.expires_at:
                approval.status = "expired"
                return False, "Approval token has expired"

            # Parameter binding check: tool_name, tenant_id, arguments must match approved action
            if approval.tool_name != request.tool_name:
                return False, f"Approval token was issued for tool '{approval.tool_name}', not '{request.tool_name}'"

            if approval.tenant_id != request.tenant_id:
                return False, "Approval token was issued for a different tenant"

            req_digest = _compute_args_digest(request.arguments)
            appr_digest = _compute_args_digest(approval.arguments)
            if req_digest != appr_digest:
                return False, "Tool arguments do not match approved parameters (parameter tampering detected)"

            # Consume token: single-use enforcement
            approval.status = "used"
            return True, "Valid approval token verified and consumed"


# Singleton store instance
approval_store = ApprovalStore()


def resolve_identity(
    api_key: Optional[str] = None,
    auth_header: Optional[str] = None,
    unverified_role: Optional[str] = None,
    unverified_user_id: Optional[str] = None,
    unverified_tenant_id: Optional[str] = None,
) -> UserIdentity:
    """Resolves caller identity from verified credentials. Never trusts unverified request bodies when keys are supplied."""
    key = api_key
    if not key and auth_header:
        if auth_header.startswith("Bearer "):
            key = auth_header.split(" ", 1)[1]
        elif auth_header.startswith("ApiKey "):
            key = auth_header.split(" ", 1)[1]
        else:
            key = auth_header

    if key:
        matched = settings.API_KEYS.get(key)
        if matched:
            return UserIdentity(
                user_id=matched.get("user_id", "authenticated_user"),
                user_role=matched.get("user_role", "read_only"),
                tenant_id=matched.get("tenant_id", "default_tenant"),
                is_authenticated=True,
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API Key provided",
            )

    if settings.REQUIRE_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: please supply a valid X-API-Key or Authorization header",
        )

    # In development / permissive mode without API key, populate from caller provided values, but marked unauthenticated
    return UserIdentity(
        user_id=unverified_user_id or "anonymous",
        user_role=unverified_role or "read_only",
        tenant_id=unverified_tenant_id or "default_tenant",
        is_authenticated=False,
    )


async def get_current_identity(
    x_api_key: Optional[str] = Security(api_key_header),
    authorization: Optional[str] = Header(None),
) -> UserIdentity:
    """FastAPI dependency for authenticating requests."""
    return resolve_identity(api_key=x_api_key, auth_header=authorization)
