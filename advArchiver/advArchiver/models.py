from dataclasses import dataclass, field


@dataclass(frozen=True)
class BackendCapabilities:
    supports_password: bool
    supports_split_volumes: bool
    supports_native_recovery: bool
    supports_external_recovery: bool
    supports_embedded_recovery: bool
    supports_comments: bool
    supports_explicit_format: bool


@dataclass
class ArchiveJob:
    backend_name: str
    item_path: str
    item_type: str
    rel_path: str
    final_output_dir: str
    tmp_dir: str = ""


@dataclass
class ArchiveArtifacts:
    archive_files: list[str] = field(default_factory=list)
    recovery_files: list[str] = field(default_factory=list)


@dataclass
class ArchiveExecutionResult:
    archive_files: list[str] = field(default_factory=list)
    error_code: int = 0
    error_msg: str = ""
    command: str = ""

    @property
    def succeeded(self) -> bool:
        return self.error_code == 0 and not self.error_msg and bool(self.archive_files)


@dataclass
class RecoveryExecutionResult:
    recovery_files: list[str] = field(default_factory=list)
    error_msg: str = ""
    command: str = ""
    embedded: bool = False

    @property
    def succeeded(self) -> bool:
        return not self.error_msg


@dataclass
class BackendExecutionResult:
    archive_result: ArchiveExecutionResult = field(
        default_factory=ArchiveExecutionResult
    )
    recovery_result: RecoveryExecutionResult | None = None
