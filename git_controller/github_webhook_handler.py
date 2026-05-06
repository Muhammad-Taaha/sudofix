"""
GitHub Webhook Handler for Repo-LLM

Handles incoming webhooks from GitHub for:
- Push events (code changes)
- Pull requests (code review)
- Release events (versioning)
"""

import hmac
import hashlib
from typing import Dict, List, Optional
from enum import Enum


class WebhookEvent(Enum):
    """Supported GitHub webhook events"""
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    RELEASE = "release"
    ISSUES = "issues"
    PULL_REQUEST_REVIEW = "pull_request_review"


class GitHubWebhookHandler:
    """
    Handles GitHub webhooks and extracts relevant information.
    Validates webhook signatures for security.
    """
    
    def __init__(self, webhook_secret: Optional[str] = None):
        """
        Initialize webhook handler.
        
        Args:
            webhook_secret: GitHub webhook secret for signature verification
        """
        self.webhook_secret = webhook_secret

    def validate_signature(self, payload: bytes, signature: str) -> bool:
        """
        Validate webhook signature against GitHub's X-Hub-Signature header.
        
        Args:
            payload: Raw request body
            signature: X-Hub-Signature header value (format: sha256=...)
        
        Returns:
            True if signature is valid, False otherwise
        """
        if not self.webhook_secret:
            # Warning: Webhook validation disabled
            return True
        
        try:
            # Extract algorithm and signature from header
            algo, provided_sig = signature.split("=", 1)
            
            # Compute expected signature
            expected_sig = hmac.new(
                self.webhook_secret.encode(),
                payload,
                hashlib.sha256
            ).hexdigest()
            
            # Compare signatures (constant-time comparison)
            return hmac.compare_digest(expected_sig, provided_sig)
        except Exception:
            return False

    def parse_push_event(self, payload: Dict) -> Dict:
        """
        Parse push event from GitHub webhook.
        
        Args:
            payload: GitHub webhook payload
        
        Returns:
            Dictionary with extracted push information
        """
        return {
            "event_type": WebhookEvent.PUSH.value,
            "repository": payload.get("repository", {}).get("full_name"),
            "branch": payload.get("ref", "").replace("refs/heads/", ""),
            "commits": [
                {
                    "hash": commit.get("id"),
                    "author": commit.get("author", {}).get("name"),
                    "email": commit.get("author", {}).get("email"),
                    "message": commit.get("message"),
                    "timestamp": commit.get("timestamp"),
                    "files_added": commit.get("added", []),
                    "files_modified": commit.get("modified", []),
                    "files_removed": commit.get("removed", []),
                }
                for commit in payload.get("commits", [])
            ],
            "pusher": payload.get("pusher", {}).get("name"),
            "timestamp": payload.get("created") or payload.get("timestamp"),
        }

    def parse_pull_request_event(self, payload: Dict) -> Dict:
        """
        Parse pull request event from GitHub webhook.
        
        Args:
            payload: GitHub webhook payload
        
        Returns:
            Dictionary with extracted PR information
        """
        pr = payload.get("pull_request", {})
        return {
            "event_type": WebhookEvent.PULL_REQUEST.value,
            "action": payload.get("action"),  # opened, closed, synchronize, etc.
            "repository": payload.get("repository", {}).get("full_name"),
            "pr_number": pr.get("number"),
            "pr_title": pr.get("title"),
            "pr_description": pr.get("body"),
            "source_branch": pr.get("head", {}).get("ref"),
            "target_branch": pr.get("base", {}).get("ref"),
            "author": pr.get("user", {}).get("login"),
            "commits": pr.get("commits"),
            "changed_files": pr.get("changed_files"),
            "additions": pr.get("additions"),
            "deletions": pr.get("deletions"),
            "timestamp": pr.get("updated_at"),
        }

    def parse_release_event(self, payload: Dict) -> Dict:
        """
        Parse release event from GitHub webhook.
        
        Args:
            payload: GitHub webhook payload
        
        Returns:
            Dictionary with extracted release information
        """
        release = payload.get("release", {})
        return {
            "event_type": WebhookEvent.RELEASE.value,
            "action": payload.get("action"),  # published, created, deleted
            "repository": payload.get("repository", {}).get("full_name"),
            "release_tag": release.get("tag_name"),
            "release_name": release.get("name"),
            "release_body": release.get("body"),
            "author": release.get("author", {}).get("login"),
            "prerelease": release.get("prerelease"),
            "draft": release.get("draft"),
            "timestamp": release.get("published_at"),
        }

    def parse_issue_event(self, payload: Dict) -> Dict:
        """
        Parse issue event from GitHub webhook.
        
        Args:
            payload: GitHub webhook payload
        
        Returns:
            Dictionary with extracted issue information
        """
        issue = payload.get("issue", {})
        return {
            "event_type": WebhookEvent.ISSUES.value,
            "action": payload.get("action"),  # opened, closed, edited, etc.
            "repository": payload.get("repository", {}).get("full_name"),
            "issue_number": issue.get("number"),
            "issue_title": issue.get("title"),
            "issue_body": issue.get("body"),
            "author": issue.get("user", {}).get("login"),
            "labels": [label.get("name") for label in issue.get("labels", [])],
            "timestamp": issue.get("updated_at"),
        }

    def get_changed_files(self, payload: Dict, event_type: str) -> List[str]:
        """
        Extract list of changed files from webhook payload.
        
        Args:
            payload: GitHub webhook payload
            event_type: Type of webhook event
        
        Returns:
            List of file paths that changed
        """
        changed_files = []
        
        if event_type == WebhookEvent.PUSH.value:
            for commit in payload.get("commits", []):
                changed_files.extend(commit.get("added", []))
                changed_files.extend(commit.get("modified", []))
                changed_files.extend(commit.get("removed", []))
        
        elif event_type == WebhookEvent.PULL_REQUEST.value:
            # PR changed files are not in the webhook by default
            # You'd need to fetch from PR API or check commit diffs
            pr = payload.get("pull_request", {})
            # This would require additional API calls
            pass
        
        return list(set(changed_files))  # Remove duplicates

    def extract_commit_shas(self, payload: Dict, event_type: str) -> List[str]:
        """
        Extract commit SHAs from webhook payload.
        
        Args:
            payload: GitHub webhook payload
            event_type: Type of webhook event
        
        Returns:
            List of commit SHAs
        """
        shas = []
        
        if event_type == WebhookEvent.PUSH.value:
            shas = [commit.get("id") for commit in payload.get("commits", [])]
        
        elif event_type == WebhookEvent.PULL_REQUEST.value:
            pr = payload.get("pull_request", {})
            shas = [pr.get("head", {}).get("sha")]
        
        return [sha for sha in shas if sha]

    def parse_webhook(self, payload: Dict) -> Optional[Dict]:
        """
        Main method to parse any GitHub webhook.
        
        Args:
            payload: GitHub webhook payload
        
        Returns:
            Parsed webhook data or None if event type not supported
        """
        event_type = payload.get("action")  # Try action field first
        if not event_type:
            # Fallback for events that use different field
            headers = payload.get("_headers", {})
            event_type = headers.get("x-github-event")
        
        # Determine event type from payload structure
        if "commits" in payload:
            event_type = WebhookEvent.PUSH.value
        elif "pull_request" in payload:
            event_type = WebhookEvent.PULL_REQUEST.value
        elif "release" in payload:
            event_type = WebhookEvent.RELEASE.value
        elif "issue" in payload:
            event_type = WebhookEvent.ISSUES.value
        
        # Parse based on event type
        if event_type == WebhookEvent.PUSH.value:
            return self.parse_push_event(payload)
        elif event_type == WebhookEvent.PULL_REQUEST.value:
            return self.parse_pull_request_event(payload)
        elif event_type == WebhookEvent.RELEASE.value:
            return self.parse_release_event(payload)
        elif event_type == WebhookEvent.ISSUES.value:
            return self.parse_issue_event(payload)
        
        return None
