"""Tests for POST /api/alerts/<workflow_run_id>/approve — Conductor WAIT gate.

Covers:
  - Unauthenticated requests are rejected (401 or 302 redirect)
  - Authenticated request calls OrkesTaskClient.update_task_sync with the
    correct workflow_id and task_ref_name (Conductor client is mocked)
  - Returns 503 when CONDUCTOR_SERVER_URL is not configured
  - Returns 503 when the conductor SDK is not installed
"""
import json
import sys
import types
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_RUN_ID = "t9ortest0000-0000-0000-0000-000000000001"


def _post_approve(client, run_id=_FAKE_RUN_ID, body=None):
    return client.post(
        f"/api/alerts/{run_id}/approve",
        data=json.dumps(body or {}),
        content_type="application/json",
    )


# ---------------------------------------------------------------------------
# Auth boundary
# ---------------------------------------------------------------------------

def test_approve_endpoint_rejects_unauthenticated(anon_client):
    """An analyst must be logged in — unauthenticated requests get 302 or 401."""
    resp = _post_approve(anon_client)
    assert resp.status_code in (302, 401), (
        f"Expected redirect-to-login (302) or 401, got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# Conductor not configured — 503 before touching the SDK
# ---------------------------------------------------------------------------

def test_approve_returns_503_when_conductor_url_not_set(client, monkeypatch):
    """Return 503 without touching the Conductor SDK when CONDUCTOR_SERVER_URL is absent."""
    monkeypatch.delenv("CONDUCTOR_SERVER_URL", raising=False)

    # Stub the SDK import so the test doesn't require conductor-python installed.
    mock_sdk = types.ModuleType("conductor")
    mock_sdk.client = types.ModuleType("conductor.client")
    mock_sdk.client.configuration = types.ModuleType("conductor.client.configuration")
    mock_sdk.client.configuration.configuration = types.ModuleType(
        "conductor.client.configuration.configuration"
    )
    mock_sdk.client.configuration.configuration.Configuration = MagicMock()
    mock_sdk.client.orkes = types.ModuleType("conductor.client.orkes")
    mock_sdk.client.orkes.orkes_task_client = types.ModuleType(
        "conductor.client.orkes.orkes_task_client"
    )
    mock_sdk.client.orkes.orkes_task_client.OrkesTaskClient = MagicMock()

    with patch.dict(sys.modules, {
        "conductor": mock_sdk,
        "conductor.client": mock_sdk.client,
        "conductor.client.configuration": mock_sdk.client.configuration,
        "conductor.client.configuration.configuration": mock_sdk.client.configuration.configuration,
        "conductor.client.orkes": mock_sdk.client.orkes,
        "conductor.client.orkes.orkes_task_client": mock_sdk.client.orkes.orkes_task_client,
    }):
        resp = _post_approve(client)

    assert resp.status_code == 503
    assert "CONDUCTOR_SERVER_URL" in resp.get_json()["error"]


# ---------------------------------------------------------------------------
# Conductor SDK not installed — 503 on ImportError
# ---------------------------------------------------------------------------

def test_approve_returns_503_when_conductor_sdk_not_installed(client, monkeypatch):
    """Return 503 when conductor-python is not installed (ImportError)."""
    monkeypatch.setenv("CONDUCTOR_SERVER_URL", "https://developer.orkescloud.com/api")

    # Force an ImportError for the conductor package.
    with patch.dict(sys.modules, {"conductor": None,
                                   "conductor.client": None,
                                   "conductor.client.configuration": None,
                                   "conductor.client.configuration.configuration": None,
                                   "conductor.client.orkes": None,
                                   "conductor.client.orkes.orkes_task_client": None}):
        resp = _post_approve(client)

    assert resp.status_code == 503
    assert "SDK" in resp.get_json()["error"] or "conductor" in resp.get_json()["error"].lower()


# ---------------------------------------------------------------------------
# Successful approval — mock Conductor, assert correct call
# ---------------------------------------------------------------------------

def _make_conductor_mocks():
    """Return (mock_task_client_cls, mock_task_client_instance, mock_configuration_cls)."""
    mock_task_client = MagicMock()
    mock_task_client.update_task_sync.return_value = MagicMock()

    mock_task_client_cls = MagicMock(return_value=mock_task_client)
    mock_configuration_cls = MagicMock(return_value=MagicMock())

    return mock_task_client_cls, mock_task_client, mock_configuration_cls


def _patch_conductor(monkeypatch, mock_task_client_cls, mock_configuration_cls):
    """Inject mock Conductor classes into sys.modules for the duration of the test."""
    mod_conf = types.ModuleType("conductor.client.configuration.configuration")
    mod_conf.Configuration = mock_configuration_cls

    mod_task = types.ModuleType("conductor.client.orkes.orkes_task_client")
    mod_task.OrkesTaskClient = mock_task_client_cls

    patches = {
        "conductor":                                          types.ModuleType("conductor"),
        "conductor.client":                                   types.ModuleType("conductor.client"),
        "conductor.client.configuration":                     types.ModuleType("conductor.client.configuration"),
        "conductor.client.configuration.configuration":       mod_conf,
        "conductor.client.orkes":                             types.ModuleType("conductor.client.orkes"),
        "conductor.client.orkes.orkes_task_client":           mod_task,
    }
    for k, v in patches.items():
        monkeypatch.setitem(sys.modules, k, v)


def test_approve_calls_update_task_sync_with_correct_args(client, monkeypatch):
    """Authenticated approval must call update_task_sync with the right workflow_id
    and task_ref_name, then return 200 with approved_by set to the current user."""
    monkeypatch.setenv("CONDUCTOR_SERVER_URL", "https://developer.orkescloud.com/api")

    mock_task_client_cls, mock_task_client, mock_configuration_cls = _make_conductor_mocks()
    _patch_conductor(monkeypatch, mock_task_client_cls, mock_configuration_cls)

    resp = _post_approve(client, run_id=_FAKE_RUN_ID, body={"note": "looks clean"})

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.get_json()}"
    body = resp.get_json()
    assert body["workflow_run_id"] == _FAKE_RUN_ID
    assert body["status"] == "released"
    assert body["approved_by"] == "tester"  # TEST_USERNAME from conftest

    # The real assertion: update_task_sync was called with the correct identifiers.
    mock_task_client.update_task_sync.assert_called_once()
    call_kwargs = mock_task_client.update_task_sync.call_args
    assert call_kwargs.kwargs.get("workflow_id") == _FAKE_RUN_ID or (
        call_kwargs.args and call_kwargs.args[0] == _FAKE_RUN_ID
    ), f"workflow_id not passed correctly: {call_kwargs}"
    assert call_kwargs.kwargs.get("task_ref_name") == "approval_wait_ref" or (
        len(call_kwargs.args) > 1 and call_kwargs.args[1] == "approval_wait_ref"
    ), f"task_ref_name not passed correctly: {call_kwargs}"


def test_approve_passes_note_in_output(client, monkeypatch):
    """The analyst's note must appear in the output dict sent to Conductor."""
    monkeypatch.setenv("CONDUCTOR_SERVER_URL", "https://developer.orkescloud.com/api")

    mock_task_client_cls, mock_task_client, mock_configuration_cls = _make_conductor_mocks()
    _patch_conductor(monkeypatch, mock_task_client_cls, mock_configuration_cls)

    _post_approve(client, body={"note": "reviewed and approved by on-call analyst"})

    call_kwargs = mock_task_client.update_task_sync.call_args
    output = call_kwargs.kwargs.get("output") or (
        call_kwargs.args[3] if len(call_kwargs.args) > 3 else {}
    )
    assert output.get("note") == "reviewed and approved by on-call analyst"
    assert output.get("approved_by") == "tester"


def test_approve_returns_502_when_conductor_raises(client, monkeypatch):
    """When update_task_sync raises (e.g. wrong workflow ID), return 502."""
    monkeypatch.setenv("CONDUCTOR_SERVER_URL", "https://developer.orkescloud.com/api")

    mock_task_client = MagicMock()
    mock_task_client.update_task_sync.side_effect = RuntimeError("not found")
    mock_task_client_cls = MagicMock(return_value=mock_task_client)
    mock_configuration_cls = MagicMock(return_value=MagicMock())
    _patch_conductor(monkeypatch, mock_task_client_cls, mock_configuration_cls)

    resp = _post_approve(client)

    assert resp.status_code == 502
    assert "conductor error" in resp.get_json()["error"]
