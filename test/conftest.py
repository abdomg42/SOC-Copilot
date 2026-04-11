# tests/phase4/conftest.py
import pytest
from unittest.mock import patch, MagicMock
from .mock_elastic import get_context_logs

@pytest.fixture(autouse=True)
def mock_external_dependencies():
    """
    Automatically patch all external dependencies for every test.
    This makes Phase 4 fully standalone — no Elasticsearch, no Wazuh needed.
    """
    with patch("agent.nodes.get_retriever") as mock_retriever, \
         patch("agent.tools.search_elastic_logs") as mock_elastic:

        # Mock RAG retriever — returns relevant passages
        mock_doc_brute = MagicMock()
        mock_doc_brute.page_content = (
            "Technique T1110.001: Password Guessing. "
            "Adversaries use lists of commonly used passwords to try to gain "
            "access to accounts. Mitigation: account lockout policy, MFA."
        )
        mock_doc_scan = MagicMock()
        mock_doc_scan.page_content = (
            "Technique T1046: Network Service Scanning. "
            "Adversaries may attempt to get a listing of services running on "
            "remote hosts using tools like Nmap."
        )
        mock_doc_runbook = MagicMock()
        mock_doc_runbook.page_content = (
            "SSH Brute Force Runbook: Block source IP with iptables. "
            "Disable password authentication. Enable fail2ban. "
            "Check auth.log for successful logins after failures."
        )

        mock_ret_instance = MagicMock()
        mock_ret_instance.invoke.return_value = [
            mock_doc_brute, mock_doc_scan, mock_doc_runbook
        ]
        mock_retriever.return_value = mock_ret_instance

        # Mock Elasticsearch tool
        mock_elastic.invoke.side_effect = lambda args: \
            get_context_logs(args.get("ip", ""), args.get("minutes", 15))

        yield