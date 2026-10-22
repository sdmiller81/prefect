"""
Tests for the credential_kwargs allowlist on AzureContainerInstanceCredentials.

`credential_kwargs` is forwarded to DefaultAzureCredential / ClientSecretCredential.
To prevent a caller with block-write access from redirecting authentication
(e.g. via `managed_identity_client_id` or `authority`), only an allowlist of safe
keys is permitted. These tests lock in that behaviour.
"""

from unittest.mock import patch

import pytest

from prefect_azure import AzureContainerInstanceCredentials


def _make_default_creds(**kwargs):
    """No SPN fields -> DefaultAzureCredential path."""
    return AzureContainerInstanceCredentials(credential_kwargs=kwargs)


def _make_spn_creds(**kwargs):
    """Full SPN fields -> ClientSecretCredential path."""
    return AzureContainerInstanceCredentials(
        client_id="legitimate-client-id",
        tenant_id="legitimate-tenant-id",
        client_secret="legitimate-secret",
        credential_kwargs=kwargs,
    )


class TestDisallowedKwargsRejected:
    """Keys that can redirect authentication must be rejected at validation time."""

    @pytest.mark.parametrize(
        "evil_kwargs",
        [
            {"managed_identity_client_id": "attacker-mi-client-id"},
            {"authority": "https://evil.attacker.example.com"},
            {"exclude_interactive_browser_credential": False, "foo": "bar"},
        ],
    )
    def test_default_path_rejects_disallowed_kwargs(self, evil_kwargs):
        with pytest.raises(ValueError, match="not permitted"):
            _make_default_creds(**evil_kwargs)

    @pytest.mark.parametrize(
        "evil_kwargs",
        [
            {"authority": "https://evil.attacker.example.com"},
            {"managed_identity_client_id": "attacker-mi-client-id"},
        ],
    )
    def test_spn_path_rejects_disallowed_kwargs(self, evil_kwargs):
        with pytest.raises(ValueError, match="not permitted"):
            _make_spn_creds(**evil_kwargs)


class TestAllowedKwargsAccepted:
    """The safe exclusion flags and logging_enable must still work."""

    def test_default_path_accepts_exclusion_flag(self):
        creds = _make_default_creds(exclude_powershell_credential=True)
        with patch("prefect_azure.credentials.DefaultAzureCredential") as mock_dac:
            creds._create_credential()
            mock_dac.assert_called_once_with(exclude_powershell_credential=True)

    def test_spn_path_accepts_logging_enable(self):
        creds = _make_spn_creds(logging_enable=True)
        with patch("prefect_azure.credentials.ClientSecretCredential") as mock_csc:
            creds._create_credential()
            _, kwargs = mock_csc.call_args
            assert kwargs.get("logging_enable") is True

    def test_spn_path_rejects_exclusion_flag_not_valid_for_client_secret(self):
        # exclusion flags are DefaultAzureCredential-only; not valid on the SPN path
        with pytest.raises(ValueError, match="not permitted"):
            _make_spn_creds(exclude_cli_credential=True)


class TestNoKwargsUnchanged:
    """The common case (no credential_kwargs) is unaffected."""

    def test_no_kwargs_forwards_nothing(self):
        creds = AzureContainerInstanceCredentials()
        with patch("prefect_azure.credentials.DefaultAzureCredential") as mock_dac:
            creds._create_credential()
            mock_dac.assert_called_once_with()
