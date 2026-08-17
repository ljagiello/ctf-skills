"""Credential management for authentication testing."""

import json
import os
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime, timezone
import hashlib


class CredentialManager:
    """
    Manage test credentials with secure storage and reusability.

    Stores credentials in .credentials files that are gitignored,
    allowing credential reuse across testing sessions while maintaining
    security and proper credential lifecycle management.
    """

    def __init__(self, credentials_file: str = ".credentials"):
        """
        Initialize credential manager.

        Args:
            credentials_file: Path to credentials file (default: .credentials in current dir)
        """
        self.credentials_file = Path(credentials_file)
        self._ensure_gitignored()

    def _ensure_gitignored(self):
        """Ensure .credentials files are gitignored."""
        gitignore_path = Path(".gitignore")

        # Check if .gitignore exists and contains .credentials pattern
        gitignore_patterns = [".credentials", "*.credentials"]
        needs_update = True

        if gitignore_path.exists():
            content = gitignore_path.read_text()
            if any(pattern in content for pattern in gitignore_patterns):
                needs_update = False

        if needs_update:
            # Add to gitignore
            mode = "a" if gitignore_path.exists() else "w"
            with open(gitignore_path, mode) as f:
                if gitignore_path.exists() and not content.endswith("\n"):
                    f.write("\n")
                f.write("\n# Test credentials (sensitive)\n")
                f.write(".credentials\n")
                f.write("*.credentials\n")

    def load_credentials(self) -> Dict[str, Dict]:
        """
        Load all credentials from file.

        Returns:
            Dictionary of credentials indexed by target domain
        """
        if not self.credentials_file.exists():
            return {}

        try:
            with open(self.credentials_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}

    def save_credentials(self, credentials: Dict[str, Dict]):
        """
        Save credentials to file.

        Args:
            credentials: Dictionary of credentials to save
        """
        with open(self.credentials_file, 'w') as f:
            json.dump(credentials, f, indent=2)

        # Ensure file has restrictive permissions (600 on Unix)
        if hasattr(os, 'chmod'):
            os.chmod(self.credentials_file, 0o600)

    def store_credential(
        self,
        target: str,
        username: str,
        password: str,
        email: Optional[str] = None,
        account_type: str = "test",
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Store a credential for a target.

        Args:
            target: Target domain or identifier (e.g., "example.com")
            username: Username or account identifier
            password: Password
            email: Email address (if different from username)
            account_type: Type of account (test, admin, user, etc.)
            metadata: Additional metadata (2FA setup, API keys, etc.)

        Returns:
            Credential ID
        """
        credentials = self.load_credentials()

        # Generate credential ID
        credential_id = hashlib.sha256(
            f"{target}:{username}:{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:16]

        # Initialize target if not exists
        if target not in credentials:
            credentials[target] = {
                "accounts": {},
                "metadata": {
                    "created": datetime.now(timezone.utc).isoformat(),
                    "last_updated": datetime.now(timezone.utc).isoformat()
                }
            }

        # Store credential
        credentials[target]["accounts"][credential_id] = {
            "username": username,
            "password": password,
            "email": email or username,
            "account_type": account_type,
            "created": datetime.now(timezone.utc).isoformat(),
            "last_used": None,
            "metadata": metadata or {}
        }

        credentials[target]["metadata"]["last_updated"] = datetime.now(timezone.utc).isoformat()

        self.save_credentials(credentials)
        return credential_id

    def get_credential(
        self,
        target: str,
        credential_id: Optional[str] = None,
        account_type: Optional[str] = None
    ) -> Optional[Dict]:
        """
        Retrieve a credential.

        Args:
            target: Target domain
            credential_id: Specific credential ID (optional)
            account_type: Filter by account type (optional)

        Returns:
            Credential dictionary or None
        """
        credentials = self.load_credentials()

        if target not in credentials:
            return None

        accounts = credentials[target]["accounts"]

        # Get specific credential
        if credential_id:
            credential = accounts.get(credential_id)
            if credential:
                # Update last_used timestamp
                credential["last_used"] = datetime.now(timezone.utc).isoformat()
                self.save_credentials(credentials)
            return credential

        # Get by account type
        if account_type:
            for cred_id, cred_data in accounts.items():
                if cred_data.get("account_type") == account_type:
                    cred_data["last_used"] = datetime.now(timezone.utc).isoformat()
                    self.save_credentials(credentials)
                    return cred_data

        # Return most recently created
        if accounts:
            latest_cred = max(
                accounts.items(),
                key=lambda x: x[1].get("created", "")
            )[1]
            latest_cred["last_used"] = datetime.now(timezone.utc).isoformat()
            self.save_credentials(credentials)
            return latest_cred

        return None

    def list_credentials(self, target: Optional[str] = None) -> Dict[str, List[Dict]]:
        """
        List all credentials.

        Args:
            target: Filter by target (optional)

        Returns:
            Dictionary of credentials by target
        """
        credentials = self.load_credentials()

        if target:
            if target in credentials:
                return {target: list(credentials[target]["accounts"].values())}
            return {}

        result = {}
        for tgt, data in credentials.items():
            result[tgt] = list(data["accounts"].values())

        return result

    def delete_credential(self, target: str, credential_id: str) -> bool:
        """
        Delete a credential.

        Args:
            target: Target domain
            credential_id: Credential ID to delete

        Returns:
            True if deleted, False if not found
        """
        credentials = self.load_credentials()

        if target not in credentials:
            return False

        if credential_id in credentials[target]["accounts"]:
            del credentials[target]["accounts"][credential_id]
            credentials[target]["metadata"]["last_updated"] = datetime.now(timezone.utc).isoformat()
            self.save_credentials(credentials)
            return True

        return False

    def cleanup_target(self, target: str) -> bool:
        """
        Remove all credentials for a target.

        Args:
            target: Target domain

        Returns:
            True if deleted, False if not found
        """
        credentials = self.load_credentials()

        if target in credentials:
            del credentials[target]
            self.save_credentials(credentials)
            return True

        return False

    def update_metadata(
        self,
        target: str,
        credential_id: str,
        metadata: Dict
    ) -> bool:
        """
        Update credential metadata (e.g., 2FA secrets, session tokens).

        Args:
            target: Target domain
            credential_id: Credential ID
            metadata: Metadata to merge

        Returns:
            True if updated, False if not found
        """
        credentials = self.load_credentials()

        if target not in credentials:
            return False

        if credential_id in credentials[target]["accounts"]:
            current_meta = credentials[target]["accounts"][credential_id].get("metadata", {})
            current_meta.update(metadata)
            credentials[target]["accounts"][credential_id]["metadata"] = current_meta
            credentials[target]["metadata"]["last_updated"] = datetime.now(timezone.utc).isoformat()
            self.save_credentials(credentials)
            return True

        return False

    def export_for_tools(
        self,
        target: str,
        credential_id: Optional[str] = None
    ) -> Optional[Dict]:
        """
        Export credential in format suitable for automation tools.

        Args:
            target: Target domain
            credential_id: Specific credential ID (optional)

        Returns:
            Dictionary with username, password, email, metadata
        """
        cred = self.get_credential(target, credential_id)
        if not cred:
            return None

        return {
            "username": cred["username"],
            "password": cred["password"],
            "email": cred["email"],
            "metadata": cred.get("metadata", {})
        }


# Convenience functions
def store_test_credential(
    target: str,
    username: str,
    password: str,
    email: Optional[str] = None,
    **kwargs
) -> str:
    """
    Store a test credential.

    Args:
        target: Target domain (e.g., "example.com")
        username: Username
        password: Password
        email: Email (optional)
        **kwargs: Additional metadata

    Returns:
        Credential ID
    """
    manager = CredentialManager()
    return manager.store_credential(
        target=target,
        username=username,
        password=password,
        email=email,
        metadata=kwargs
    )


def get_test_credential(target: str, account_type: str = "test") -> Optional[Dict]:
    """
    Retrieve a test credential.

    Args:
        target: Target domain
        account_type: Account type filter

    Returns:
        Credential dictionary or None
    """
    manager = CredentialManager()
    return manager.get_credential(target, account_type=account_type)


def list_test_credentials(target: Optional[str] = None) -> Dict[str, List[Dict]]:
    """
    List all stored test credentials.

    Args:
        target: Filter by target (optional)

    Returns:
        Dictionary of credentials by target
    """
    manager = CredentialManager()
    return manager.list_credentials(target)
