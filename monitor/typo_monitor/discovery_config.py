"""Sanitize optional Amass v4 provider configuration without copying secrets."""

from pathlib import Path

import yaml


_MAX_CONFIG_BYTES = 1024 * 1024


def provider_config(path=None):
    """Return an effective YAML mapping containing only a provider-file pointer.

    Always pass the result as an explicit private Amass configuration, including
    when ``path`` is absent, to avoid loading a user's unrelated default config.
    Credential-file contents are never read or returned by this helper.
    """
    if path is None:
        return {"options": {}}
    try:
        config_path = Path(path).expanduser().resolve(strict=True)
        if not config_path.is_file():
            raise ValueError("Amass provider configuration must be a regular YAML file.")
        with config_path.open("rb") as source:
            content = source.read(_MAX_CONFIG_BYTES + 1)
    except (OSError, RuntimeError, TypeError) as exc:
        raise ValueError("Amass provider configuration could not be read.") from exc
    if len(content) > _MAX_CONFIG_BYTES:
        raise ValueError("Amass provider configuration exceeds the 1 MiB limit.")
    try:
        document = yaml.safe_load(content.decode("utf-8"))
    except (UnicodeError, yaml.YAMLError, RecursionError):
        # YAML diagnostics may contain source lines, including credentials.
        raise ValueError("Amass provider configuration must contain valid UTF-8 YAML.") from None
    if document is None:
        document = {}
    if not isinstance(document, dict) or any(key != "options" for key in document):
        raise ValueError("Amass provider configuration permits only 'options.datasources'; scope and scan settings are managed by the monitor.")
    options = document.get("options", {})
    if not isinstance(options, dict) or any(key != "datasources" for key in options):
        raise ValueError("Amass provider configuration permits only 'options.datasources'; database, active, brute force, alterations and other overrides are not accepted.")
    if "datasources" not in options:
        return {"options": {}}
    value = options["datasources"]
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError("Amass 'options.datasources' must name a separate provider credential file.")
    try:
        credentials = Path(value).expanduser()
        if not credentials.is_absolute():
            credentials = config_path.parent / credentials
        credentials = credentials.resolve(strict=True)
        if not credentials.is_file():
            raise ValueError("Amass provider credentials must be a regular file.")
    except (OSError, RuntimeError) as exc:
        raise ValueError("The Amass provider credential file is unavailable.") from exc
    return {"options": {"datasources": str(credentials)}}
