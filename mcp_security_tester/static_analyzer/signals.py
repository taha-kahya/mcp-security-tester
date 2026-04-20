"""
Detection pattern lists for static poisoning signal analysis.
All matches are case-insensitive substring checks.
"""

IMPERATIVE_VERBS: list[str] = [
    "read", "send", "delete", "upload", "download", "execute",
    "exfiltrate", "transmit", "copy", "move", "write", "fetch",
    "retrieve", "collect", "forward", "redirect", "steal",
    "harvest", "extract", "dump", "access", "open", "leak",
]

SECRECY_DIRECTIVES: list[str] = [
    "do not inform", "do not tell", "do not notify", "do not log",
    "do not mention", "do not report", "do not reveal", "do not show",
    "do not disclose", "keep secret", "keep hidden", "hide this",
    "silently", "without notifying", "without informing", "without telling",
    "without user knowledge", "without the user", "user must not know",
    "invisible to", "without user awareness", "covertly", "in the background",
    "user should not", "do not alert", "do not warn",
]

SENSITIVE_PATHS: list[str] = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/sudoers",
    "~/.ssh/", "id_rsa", "id_ed25519", "authorized_keys", "known_hosts",
    ".env", "~/.aws/", "~/.gcp/", "credentials", "private_key",
    "secret_key", "api_key", "access_token", "auth_token", "bearer",
    "/home/", "/root/", "~/.bash_history", "~/.zsh_history",
    "~/.netrc", "~/.gitconfig", "~/.npmrc", "~/.pypirc",
]

# Zero-width and invisible Unicode characters
HIDDEN_TEXT_CHARS: list[str] = [
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\ufeff",  # byte order mark / zero width no-break space
    "\u2060",  # word joiner
    "\u202e",  # right-to-left override
    "\u202d",  # left-to-right override
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
]

# Minimum consecutive whitespace newlines to flag as suspicious padding
HIDDEN_WHITESPACE_THRESHOLD = 8
