"""Unit tests for ToolAuthorizer: RBAC, cross-tenant isolation, argument checks, and approval gates."""

from shield.core.models import ActionDecision, ToolCallRequest
from shield.guards.tool_authorizer import ToolAuthorizer


def test_authorized_tool_allowed_for_role():
    authorizer = ToolAuthorizer()
    req = ToolCallRequest(
        user_id="user_123",
        user_role="read_only",
        tenant_id="acme_corp",
        tool_name="search_documents",
        arguments={"query": "release notes"},
    )
    decision = authorizer.authorize(req)

    assert decision.allowed is True
    assert decision.decision == ActionDecision.ALLOW
    assert decision.requires_human_approval is False


def test_unauthorized_tool_blocked_for_role():
    authorizer = ToolAuthorizer()
    req = ToolCallRequest(
        user_id="user_123",
        user_role="read_only",
        tenant_id="acme_corp",
        tool_name="send_email",
        arguments={"to": "client@example.com"},
    )
    decision = authorizer.authorize(req)

    assert decision.allowed is False
    assert decision.decision == ActionDecision.BLOCK
    assert "not authorized" in decision.reason


def test_developer_role_permitted_dev_tools_only():
    authorizer = ToolAuthorizer()
    dev_req = ToolCallRequest(
        user_role="developer",
        tool_name="run_tests",
        tenant_id="acme_corp",
    )
    assert authorizer.authorize(dev_req).allowed is True

    admin_tool_req = ToolCallRequest(
        user_role="developer",
        tool_name="update_permissions",
        tenant_id="acme_corp",
    )
    decision = authorizer.authorize(admin_tool_req)
    assert decision.allowed is False
    assert decision.decision == ActionDecision.BLOCK


def test_cross_tenant_violation_blocked():
    authorizer = ToolAuthorizer()
    req = ToolCallRequest(
        user_role="admin",
        tenant_id="tenant_alpha",
        tool_name="search_documents",
        arguments={"tenant_id": "tenant_beta", "query": "financials"},
    )
    decision = authorizer.authorize(req)

    assert decision.allowed is False
    assert decision.decision == ActionDecision.BLOCK
    assert "Cross-tenant access violation" in decision.reason


def test_exfiltration_destination_domain_blocked():
    authorizer = ToolAuthorizer()
    req = ToolCallRequest(
        user_role="admin",
        tenant_id="acme_corp",
        tool_name="search_documents",
        arguments={"callback_url": "https://webhook.site/malicious-endpoint"},
    )
    decision = authorizer.authorize(req)

    assert decision.allowed is False
    assert decision.decision == ActionDecision.BLOCK
    assert "prohibited host" in decision.reason


def test_high_risk_tool_requires_human_approval():
    authorizer = ToolAuthorizer()
    req = ToolCallRequest(
        user_role="admin",
        tenant_id="acme_corp",
        tool_name="send_email",
        arguments={"to": "investor@corp.com", "body": "Monthly report"},
    )
    decision = authorizer.authorize(req)

    assert decision.allowed is False
    assert decision.decision == ActionDecision.REQUIRE_APPROVAL
    assert decision.requires_human_approval is True
    assert "explicit human reviewer" in decision.reason
