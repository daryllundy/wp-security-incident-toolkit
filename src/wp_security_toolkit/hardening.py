from __future__ import annotations

from pathlib import Path


class WordPressHardening:
    def __init__(self, wp_root: str | Path) -> None:
        self.wp_root = Path(wp_root)
        self.wp_config = self.wp_root / "wp-config.php"

    def secure_wp_config(self) -> list[str]:
        actions = []
        if not self.wp_config.exists():
            return ["wp-config.php not found"]
        content = self.wp_config.read_text(encoding="utf-8", errors="ignore")
        updates = {
            "DISALLOW_FILE_EDIT": "true",
            "FORCE_SSL_ADMIN": "true",
        }
        for key, value in updates.items():
            if f"{key}" not in content:
                content += f"\ndefine('{key}', {value});\n"
                actions.append(f"Added {key} to wp-config.php")
        self._write_with_backup(content)
        return actions

    def remove_version_info(self) -> list[str]:
        actions = []
        if not self.wp_config.exists():
            return ["wp-config.php not found"]
        content = self.wp_config.read_text(encoding="utf-8", errors="ignore")
        if "WP_HIDE_VERSION" not in content:
            content += "\ndefine('WP_HIDE_VERSION', true);\n"
            actions.append("Added WP_HIDE_VERSION flag")
        self._write_with_backup(content)
        return actions

    def disable_file_editing(self) -> list[str]:
        return self.secure_wp_config()

    def strengthen_authentication(self) -> list[str]:
        actions = []
        if not self.wp_config.exists():
            return ["wp-config.php not found"]
        content = self.wp_config.read_text(encoding="utf-8", errors="ignore")
        if "AUTH_KEY" not in content:
            content += "\n// TODO: Add unique authentication keys.\n"
            actions.append("Flagged missing authentication keys")
        self._write_with_backup(content)
        return actions

    def _write_with_backup(self, content: str) -> None:
        backup_path = self.wp_config.with_suffix(".php.bak")
        if self.wp_config.exists():
            backup_path.write_text(
                self.wp_config.read_text(encoding="utf-8", errors="ignore"),
                encoding="utf-8",
            )
        self.wp_config.write_text(content, encoding="utf-8")
