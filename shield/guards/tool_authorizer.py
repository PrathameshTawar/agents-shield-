"""Tool authorization policy engine enforcing RBAC, argument inspection, and human review gates."""

from typing import Any, Dict, List, Optional, Set
from shield.core.models import ActionDecision, ToolAuthDecision, ToolCallRequest


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
        },
    }

    RISKY_TOOLS_REQUIRING_HUMAN_APPROVAL: Set[str] = {
        "send_email",
        "delete_resource",
        "update_permissions",
        "deploy_to_production",
        "transfer_funds",
    }

    UNAUTHORIZED_DOMAINS: Set[str] = {
        "attacker.com",
        "webhook.site",
        "requestbin.com",
        "pipedream.net",
    }

    def __init__(self, custom_role_permissions: Optional[Dict[str, Set[str]]] = None):
        self.role_permissions = custom_role_permissions or self.ROLE_PERMISSIONS

    def authorize(self, request: ToolCallRequest) -> ToolAuthDecision:
        """Evaluates whether the tool call request complies with RBAC, tenant boundaries, and destination policies."""
        allowed_tools = self.role_permissions.get(request.user_role, set())

        # 1. Role permission check
        if request.tool_name not in allowed_tools:
            return ToolAuthDecision(
                allowed=False,
                decision=ActionDecision.BLOCK,
                requires_human_approval=False,
                reason=f"Role '{request.user_role}' is not authorized to invoke tool '{request.tool_name}'",
                tool_name=request.tool_name,
            )

        # 2. Tenant isolation check: arguments cannot reference foreign tenant
        arg_tenant = request.arguments.get("tenant_id")
        if arg_tenant and arg_tenant != request.tenant_id:
            return ToolAuthDecision(
                allowed=False,
                decision=ActionDecision.BLOCK,
                requires_human_approval=False,
                reason=f"Cross-tenant access violation: user tenant '{request.tenant_id}' cannot access '{arg_tenant}'",
                tool_name=request.tool_name,
            )

        # 3. Argument destination check (exfiltration / suspicious URL defense)
        for key, val in request.arguments.items():
            if isinstance(val, str):
                lower_val = val.lower()
                for bad_domain in self.UNAUTHORIZED_DOMAINS:
                    if bad_domain in lower_val:
                        return ToolAuthDecision(
                            allowed=False,
                            decision=ActionDecision.BLOCK,
                            requires_human_approval=False,
                            reason=f"Destination parameter in argument '{key}' routes to prohibited host '{bad_domain}'",
                            tool_name=request.tool_name,
                        )

        # 4. Human approval gate for high-risk actions
        if request.tool_name in self.RISKY_TOOLS_REQUIRING_HUMAN_APPROVAL:
            return ToolAuthDecision(
                allowed=False,
                decision=ActionDecision.REQUIRE_APPROVAL,
                requires_human_approval=True,
                reason=f"High-risk action '{request.tool_name}' requires explicit human reviewer authorization",
                tool_name=request.tool_name,
            )

        # 5. Clean authorization
        return ToolAuthDecision(
            allowed=True,
            decision=ActionDecision.ALLOW,
            requires_human_approval=False,
            reason="Tool action authorized under active role policies",
            tool_name=request.tool_name,
        )
