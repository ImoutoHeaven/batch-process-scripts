import time
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class FailureRecord:
    item_type: str
    path: str
    error_code: int
    error_msg: str
    command: str
    timestamp: str


@dataclass(frozen=True)
class RecoveryWarningRecord:
    item_type: str
    path: str
    archive_files: list[str] = field(default_factory=list)
    timestamp: str = ""


class CompressionStats:
    def __init__(self):
        self.success_files = 0
        self.success_folders = 0
        self.failed_files = 0
        self.failed_folders = 0
        self.failed_items = []
        self.recovery_warning_items = []
        self.start_time = time.time()

    @property
    def hard_failure_count(self):
        return self.failed_files + self.failed_folders

    @property
    def recovery_warning_count(self):
        return len(self.recovery_warning_items)

    def add_success(self, item_type, item_path):
        del item_path
        if item_type == "file":
            self.success_files += 1
        else:
            self.success_folders += 1

    def add_failure(self, item_type, item_path, error_code, error_msg, cmd_str):
        if item_type == "file":
            self.failed_files += 1
        else:
            self.failed_folders += 1

        self.failed_items.append(
            FailureRecord(
                item_type=item_type,
                path=item_path,
                error_code=error_code,
                error_msg=error_msg,
                command=cmd_str,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        )

    def add_recovery_warning(self, item_type, item_path, archive_files):
        self.recovery_warning_items.append(
            RecoveryWarningRecord(
                item_type=item_type,
                path=item_path,
                archive_files=list(archive_files),
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        )
