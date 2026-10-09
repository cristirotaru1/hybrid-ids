import os
import stat
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path


class RulesRepository:
    _mutation_lock = threading.RLock()

    def __init__(self, rules_dir: Path, rules_file: str):
        self.rules_dir = Path(rules_dir)
        self.rules_file = rules_file

    @property
    def path(self) -> Path:
        return Path(self.rules_dir) / self.rules_file

    def read_all_lines(self) -> list[str]:
        return self.path.read_text(encoding="utf-8").splitlines(keepends=True)

    @contextmanager
    def mutation_lock(self):
        """Serialize each complete read/validate/write/reload transaction."""
        with self._mutation_lock:
            yield

    def snapshot(self) -> bytes:
        """Return the exact current contents for rollback."""
        return self.path.read_bytes()

    def restore(self, snapshot: bytes) -> None:
        self._atomic_write_bytes(snapshot)

    def read_active_lines(self) -> list[tuple[int, str]]:
        lines = []

        for line_number, line in enumerate(self.read_all_lines(), start=1):
            stripped = line.strip()

            if not stripped:
                continue

            if stripped.startswith("#"):
                continue

            lines.append((line_number, stripped))

        return lines

    def comment_line(self, line_number: int) -> None:
        lines = self.read_all_lines()
        index = line_number - 1

        if index < 0 or index >= len(lines):
            raise IndexError(f"Line {line_number} is out of range")

        original = lines[index]

        if original.endswith("\r\n"):
            newline = "\r\n"
            content = original[:-2]
        elif original.endswith("\n"):
            newline = "\n"
            content = original[:-1]
        else:
            newline = ""
            content = original

        lines[index] = f"# {content}{newline}"
        self._atomic_write_text("".join(lines))

    def replace_line(self, line_number: int, raw_rule: str) -> None:
        raw_rule = raw_rule.strip()
        if not raw_rule:
            raise ValueError("Rule text cannot be empty")

        lines = self.read_all_lines()
        index = line_number - 1

        if index < 0 or index >= len(lines):
            raise IndexError(f"Line {line_number} is out of range")

        original = lines[index]

        if original.endswith("\r\n"):
            newline = "\r\n"
        elif original.endswith("\n"):
            newline = "\n"
        else:
            newline = "\n"

        lines[index] = f"{raw_rule}{newline}"
        self._atomic_write_text("".join(lines))

    def append_rule(self, raw_rule: str) -> int:
        raw_rule = raw_rule.strip()

        if not raw_rule:
            raise ValueError("Rule text cannot be empty")

        content = self.path.read_text(encoding="utf-8") if self.path.exists() else ""
        if content and not content.endswith("\n"):
            content += "\n"
        content += raw_rule + "\n"
        self._atomic_write_text(content)

        return self._get_last_line_number()

    def _get_last_line_number(self) -> int:
        return len(self.path.read_text(encoding="utf-8").splitlines())

    def _atomic_write_text(self, content: str) -> None:
        self._atomic_write_bytes(content.encode("utf-8"))

    def _atomic_write_bytes(self, content: bytes) -> None:
        """Replace the file atomically while preserving its permission bits."""
        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        original_stat = path.stat() if path.exists() else None
        original_mode = stat.S_IMODE(original_stat.st_mode) if original_stat else 0o644
        temp_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=path.parent,
                prefix=f".{path.name}.",
                delete=False,
            ) as temp_file:
                temp_path = Path(temp_file.name)
                temp_file.write(content)
                temp_file.flush()
                os.fsync(temp_file.fileno())

            os.chmod(temp_path, original_mode)
            if original_stat is not None:
                os.chown(temp_path, original_stat.st_uid, original_stat.st_gid)
            os.replace(temp_path, path)
            temp_path = None
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
