"""Tool authorization policy engine enforcing RBAC, recursive argument inspection, and human review gates."""

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from shield.core.auth import approval_store
from shield.core.config import settings
from shield.core.models import ActionDecision, ToolAuthDecision, ToolCallRequest

# Pattern to extract candidate URLs from arbitrary text
URL_REGEX = re.compile(r"https?://[^\s/$.?#].[^\s]*", re.IGNORECASE)


class ToolAuthorizer:
    """Independent policy interceptor that validates proposed agent tool actions before execution."""

    ROLE_PERMISSIONS: Dict[str, Set[str]] = {
        "read_only": {
            "search_documents",
            "get_ticket_status",
            "list_files",
            "read_file",
            "get_metrics",
        },
        "developer": {
            "search_documents",
            "get_ticket_status",
            "list_files",
            "read_file",
            "get_metrics",
            "run_tests",
            "create_branch",
            "propose_patch",
        },
        "admin": {
            "search_documents",
            "get_ticket_status",
            "list_files",
            "read_file",
            "get_metrics",
            "run_tests",
            "create_branch",
            "propose_patch",
            "send_email",
            "delete_resource",
            "update_permissions",
            "deploy_to_production",
            "transfer_funds",
        },
    }

    RISKY_TOOLS_REQUIRING_HUMAN_APPROVAL: Set[str] = {
        "send_email",
        "delete_resource",
        "update_permissions",
        "deploy_to_production",
        "transfer_funds",
    }

    TENANT_FIELD_NAMES: Set[str] = {
        "tenant_id",
        "tenant",
        "target_tenant",
        "organization_id",
        "org_id",
    }

    def __init__(
        self,
        custom_role_permissions: Optional[Dict[str, Set[str]]] = None,
        allowed_domains: Optional[Set[str]] = None,
        unauthorized_domains: Optional[Set[str]] = None,
        enforce_allowlist: bool = False,
    ):
        self.role_permissions = custom_role_permissions or self.ROLE_PERMISSIONS
        self.allowed_domains = allowed_domains or settings.ALLOWED_DESTINATION_DOMAINS
        self.unauthorized_domains = unauthorized_domains or settings.PROHIBITED_DOMAINS
        self.enforce_allowlist = enforce_allowlist

    def _extract_hostnames_from_string(self, text: str) -> List[Tuple[str, str]]:
        """Extracts (url, hostname) pairs from a string."""
        results = []
        for match in URL_REGEX.finditer(text):
            raw_url = match.group(0).rstrip(".,;)>'\"]")
            try:
                parsed = urlparse(raw_url)
                if parsed.hostname:
                    results.append((raw_url, parsed.hostname.lower()))
            except Exception:
                continue
        return results

    def _walk_arguments_for_violations(
        self,
        obj: Any,
        user_tenant: str,
        path: str = "root",
    ) -> Optional[Tuple[str, str]]:
        """Recursively walks nested arguments checking for cross-tenant violations and prohibited host destinations.

        Returns (violation_type, violation_message) or None.
        """
        if isinstance(obj, dict):
            for k, v in obj.items():
                current_path = f"{path}.{k}"
                # 1. Cross-tenant inspection
                if str(k).lower() in self.TENANT_FIELD_NAMES:
                    if isinstance(v, str) and v and v != user_tenant:
                        return (
                            "cross_tenant",
                            f"Cross-tenant access violation at '{current_path}': user tenant '{user_tenant}' cannot access '{v}'",
                        )

                # Recursive walk on value
                violation = self._walk_arguments_for_violations(v, user_tenant, current_path)
                if violation:
                    return violation

        elif isinstance(obj, (list, tuple, set)):
            for idx, item in enumerate(obj):
                current_path = f"{path}[{idx}]"
                violation = self._walk_arguments_for_violations(item, user_tenant, current_path)
                if violation:
                    return violation

        elif isinstance(obj, str):
            # Check for URL destinations inside string values
            urls_and_hosts = self._extract_hostnames_from_string(obj)
            for raw_url, host in urls_and_hosts:
                # Check prohibited blocklist with proper hostname comparison
                for bad_domain in self.unauthorized_domains:
                    if host == bad_domain or host.endswith("." + bad_domain):
                        return (
                            "prohibited_domain",
                            f"Destination parameter at '{path}' routes to prohibited host '{bad_domain}' (found '{raw_url}')",
                        )

                # Optional allowlist check
                if self.enforce_allowlist:
                    is_allowed = any(
                        host == allowed or host.endswith("." + allowed)
                        for allowed in self.allowed_domains
                    )
                    if not is_allowed:
                        return (
                            "unapproved_domain",
                            f"Destination host '{host}' at '{path}' is not in approved allowlist",
                        )

        return None

    def authorize(self, request: ToolCallRequest) -> ToolAuthDecision:
        """Evaluates whether the tool call request complies with RBAC, tenant boundaries, destination policies, and approvals."""
        allowed_tools = self.role_permissions.get(request.user_role, set())

        # 1. Role permission check (RBAC)
        if request.tool_name not in allowed_tools:
            return ToolAuthDecision(
                allowed=False,
                decision=ActionDecision.BLOCK,
                requires_human_approval=False,
                reason=f"Role '{request.user_role}' is not authorized to invoke tool '{request.tool_name}'",
                tool_name=request.tool_name,
            )

        # 2. Recursive arguments inspection (cross-tenant & host destination check)
        violation = self._walk_arguments_for_violations(request.arguments, request.tenant_id)
        if violation:
            _, msg = violation
            return ToolAuthDecision(
                allowed=False,
                decision=ActionDecision.BLOCK,
                requires_human_approval=False,
                reason=msg,
                tool_name=request.tool_name,
            )

        # 3. Human approval gate for high-risk actions
        if request.tool_name in self.RISKY_TOOLS_REQUIRING_HUMAN_APPROVAL:
            # Check if an approval token was provided
            if request.approval_token:
                valid, msg = approval_store.validate_and_consume_token(request.approval_token, request)
                if valid:
                    return ToolAuthDecision(
                        allowed=True,
                        decision=ActionDecision.ALLOW,
                        requires_human_approval=False,
                        reason="Tool action authorized via verified single-use human approval token",
                        tool_name=request.tool_name,
                    )
                else:
                    return ToolAuthDecision(
                        allowed=False,
                        decision=ActionDecision.BLOCK,
                        requires_human_approval=False,
                        reason=f"Human approval token rejected: {msg}",
                        tool_name=request.tool_name,
                    )

            # No token provided; generate pending approval request
            pending = approval_store.create_approval(request)
            return ToolAuthDecision(
                allowed=False,
                decision=ActionDecision.REQUIRE_APPROVAL,
                requires_human_approval=True,
                approval_id=pending.approval_id,
                reason=f"High-risk action '{request.tool_name}' requires explicit human reviewer authorization (Approval ID: {pending.approval_id})",
                tool_name=request.tool_name,
            )

        # 4. Clean authorization
        return ToolAuthDecision(
            allowed=True,
            decision=ActionDecision.ALLOW,
            requires_human_approval=False,
            reason="Tool action authorized under active role policies",
            tool_name=request.tool_name,
        )
