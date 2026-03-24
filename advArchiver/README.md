# advArchiver

`advArchiver/advArchiver.py` is the only maintained unified advArchiver entrypoint on this branch. Frozen legacy scripts now live under `advArchiver/deprecated/adv7z.py`, `advArchiver/deprecated/advRar.py`, and `advArchiver/deprecated/advZip.py`; the old top-level paths have been removed and are no longer part of the maintained CLI surface.

## Current Layout

- `advArchiver/advArchiver.py`: maintained unified entrypoint.
- `advArchiver/advArchiver/cli.py`: shared CLI contract for `7z`, `rar`, `zip`, and `tar`.
- `advArchiver/advArchiver/engine.py`: shared archive/recovery engine, exit-code handling, and delete gating.
- `advArchiver/advArchiver/backends/`: backend-specific command construction, artifact naming, and recovery policy.
- `advArchiver/advArchiver/recovery/`: external `parpar` and inline RAR recovery providers.
- `advArchiver/deprecated/`: frozen legacy scripts preserved outside the maintained source tree.
- `advArchiver/scripts/build_single_file.py`: deterministic build helper for the generated single-file distribution entrypoint.
- `advArchiver/dist/advArchiver.py`: generated single-file output created by `advArchiver/scripts/build_single_file.py`.
- `advArchiver/tests/`: parser, backend policy, deprecation, and engine coverage.
- `advArchiver/tests/test_real_cli_guardrails.py`: real-binary guardrails for archive creation, suffix rules, recovery policy, and maintained workflow drift.
- `.github/workflows/advarchiver-integration.yml`: blocking self-hosted integration lane for build generation and real-binary guardrails.

## Maintained CLI Surface

- Maintained form: `python3 advArchiver/advArchiver.py {7z,rar,zip,tar} ...`
- Shared flags: `--dry-run`, `--depth`, `-d/--delete`, `-t/--threads`, `--rec-threads`, `--debug`, `--no-lock`, `--lock-timeout`, `--out`, `--no-rec`, `--skip-files`, `--skip-folders`, `--ext-skip-folder-tree`, and dynamic `--skip-<ext>`.
- `--threads` limits archive-job concurrency. `--rec-threads` limits separate recovery work and defaults to `max(1, os.cpu_count() // 2)` with fallback `4`.
- Recovery providers: `7z`, `zip`, and `tar` use `parpar`; `rar` keeps native inline recovery; `tar` requires `--format`.
- Deprecated scripts are preserved only under `advArchiver/deprecated/`; the old top-level paths have been removed and no compatibility entrypoints remain in the maintained surface.

## Build and Distribution

- Generate the single-file distribution script with `python3 advArchiver/scripts/build_single_file.py`.
- The builder emits `advArchiver/dist/advArchiver.py`, marks it `AUTO-GENERATED, DO NOT EDIT`, and only packages the maintained modules under `advArchiver/advArchiver/`.
- `advArchiver/dist/advArchiver.py` is a generated artifact, not the source of truth. Re-run `advArchiver/scripts/build_single_file.py` after source changes instead of editing the dist file by hand.

## Real-Binary Guardrails

- `python3 -m unittest advArchiver.tests.test_build_single_file advArchiver.tests.test_real_cli_guardrails -v` runs the blocking build-contract and real-binary guardrail suites.
- The suite exercises the maintained CLI surface via `python3 advArchiver/advArchiver.py {7z,rar,zip,tar} ...` rather than calling the shared engine directly.
- The suite covers real archive creation for `7z`, `rar`, `zip`, and `tar`, output suffix and location checks, `7z` split recovery staying external-only, tar-family archive creation uses `7z`, tar directory inputs archive contents like `zip` and `7z`, TAR alias suffix preservation, and `--no-rec` versus default recovery behavior.
- Local runs skip the binary-dependent assertions when a required tool is unavailable.
- `.github/workflows/advarchiver-integration.yml` is the blocking CI lane that provisions a self-hosted runner, verifies the required binaries (`7z`, `rar`, `parpar`) are present, smoke-tests `advArchiver/advArchiver.py --help`, runs `advArchiver/scripts/build_single_file.py`, and executes `advArchiver.tests.test_build_single_file` plus `advArchiver.tests.test_real_cli_guardrails`; tar helper binaries are no longer required maintained dependencies.

## Backend Summary

### 7z

- Supports passwords, split profiles such as `parted-10g` / `best-10g`, `--no-emb`, and `--no-rec`.
- Single non-split output defaults to append-embed recovery. Split output and `--no-emb` use external `.par2`.

### zip

- Supports passwords, `--profile`, `--code-page`, and external `parpar` recovery by default.
- `--no-rec` disables external recovery.

### rar

- Supports passwords, `--profile`, `-c/--comments`, and `-cp/--comments-path`.
- Native recovery records remain inline archive work by default. `--no-rec` disables them.

### tar

- Uses `--format` instead of `--profile`.
- Supported formats: `tar`, `tar.gz`, `tgz`, `tar.xz`, `txz`, `tar.bz2`, `tbz2`.
- No password or split-volume support. Recovery is external `parpar` only.
- Tar-family archive creation uses `7z`; tar helper binaries are no longer required maintained dependencies.
- Directory inputs archive contents like `zip` and `7z` instead of preserving the top-level folder inside tar-family archives.

## Compatibility Inventory

### 7z

- Preserved legacy flags: `--profile`, `--no-emb`, `--no-rec`, `-p/--password`.
- Preserved defaults: `--profile=best`; single non-split output stays append-embed by default.
- Preserved special behaviors:
  - split output stays external-only for recovery data
  - legacy `delete-inside-native-command` behavior stays in the native `7z` command via `-sdel`
  - split artifacts keep `*.7z.001`, `*.7z.002`, ... suffixes
- Intentional deltas:
  - maintained invocation is `python3 advArchiver/advArchiver.py 7z ...`; the legacy script is preserved only as `advArchiver/deprecated/adv7z.py`
    - why: the maintained CLI surface is the unified entrypoint, and the old top-level path has been removed
    - coverage: `advArchiver/tests/test_cli_contract.py::TestCliContract.test_top_level_lists_expected_subcommands`, `advArchiver/tests/test_deprecated_entrypoints.py::TestDeprecatedScriptLayout.test_top_level_legacy_entrypoints_are_removed`
  - shared `--rec-threads` now throttles separate recovery work
    - why: keep `parpar` concurrency separate from archive-job concurrency
    - coverage: `advArchiver/tests/test_cli_contract.py::TestCliContract.test_shared_argument_surface_exists_on_all_subcommands`, `advArchiver/tests/test_recovery_policies.py::TestRecoveryScheduling.test_external_recovery_honors_rec_threads_budget`
- Current tests:
  - `advArchiver/tests/test_7z_backend.py::TestSevenZipBackend.test_delete_preserves_legacy_sdel_behavior`
  - `advArchiver/tests/test_7z_backend.py::TestSevenZipBackend.test_dry_run_skips_7z_subprocess_execution`
  - `advArchiver/tests/test_7z_backend.py::TestSevenZipBackend.test_parted_profile_forces_external_recovery`
  - `advArchiver/tests/test_7z_backend.py::TestSevenZipBackend.test_single_archive_defaults_to_append_embed`
  - `advArchiver/tests/test_7z_backend.py::TestSevenZipBackend.test_find_and_rename_split_archives_preserves_volume_suffixes`

### zip

- Preserved legacy flags: `--profile`, `--code-page`, `--no-rec`, `-p/--password`.
- Preserved defaults: `--profile=best`; `--code-page=mcu`; recovery stays external by default.
- Preserved special behaviors:
  - legacy `delete-inside-native-command` behavior stays in the native ZIP command via `-sdel`
  - numeric code pages still map to `-mcp=<codepage>`
  - `mcu` still maps to `-mcu=on`
- Intentional deltas:
  - maintained invocation is `python3 advArchiver/advArchiver.py zip ...`; the legacy script is preserved only as `advArchiver/deprecated/advZip.py`
    - why: the maintained CLI surface is the unified entrypoint, and the old top-level path has been removed
    - coverage: `advArchiver/tests/test_cli_contract.py::TestCliContract.test_top_level_lists_expected_subcommands`, `advArchiver/tests/test_deprecated_entrypoints.py::TestDeprecatedScriptLayout.test_top_level_legacy_entrypoints_are_removed`
  - shared `--rec-threads` now throttles separate recovery work
    - why: keep `parpar` concurrency separate from archive-job concurrency
    - coverage: `advArchiver/tests/test_cli_contract.py::TestCliContract.test_shared_argument_surface_exists_on_all_subcommands`, `advArchiver/tests/test_recovery_policies.py::TestRecoveryScheduling.test_external_recovery_honors_rec_threads_budget`
- Current tests:
  - `advArchiver/tests/test_zip_backend.py::TestZipBackend.test_zip_preserves_numeric_code_page_switch`
  - `advArchiver/tests/test_zip_backend.py::TestZipBackend.test_zip_preserves_legacy_mcu_default`
  - `advArchiver/tests/test_zip_backend.py::TestZipBackend.test_zip_delete_preserves_legacy_sdel_behavior`
  - `advArchiver/tests/test_zip_backend.py::TestZipBackend.test_zip_delete_stays_in_native_archive_command_during_dry_run`
  - `advArchiver/tests/test_zip_backend.py::TestZipBackend.test_zip_defaults_to_external_parpar_recovery`
  - `advArchiver/tests/test_zip_backend.py::TestZipBackend.test_zip_no_rec_disables_external_recovery`

### rar

- Preserved legacy flags: `--profile`, `-c/--comments`, `-cp/--comments-path`, `-p/--password`.
- Preserved defaults: `--profile=best`; native recovery stays enabled by default.
- Preserved special behaviors:
  - native recovery remains inline archive work and does not use the recovery executor
  - inline native recovery still stays on `--threads`, not `--rec-threads`
  - legacy `delete-inside-native-command` behavior stays in the native RAR command via `-df`
  - split profiles still preserve native volume sizing switches such as `-v10g`
  - comment-file input still preserves the native `-z<path>` switch behavior
- Intentional deltas:
  - maintained invocation is `python3 advArchiver/advArchiver.py rar ...`; the legacy script is preserved only as `advArchiver/deprecated/advRar.py`
    - why: the maintained CLI surface is the unified entrypoint, and the old top-level path has been removed
    - coverage: `advArchiver/tests/test_cli_contract.py::TestCliContract.test_top_level_lists_expected_subcommands`, `advArchiver/tests/test_deprecated_entrypoints.py::TestDeprecatedScriptLayout.test_top_level_legacy_entrypoints_are_removed`
  - shared `--no-rec` now disables native recovery records on RAR too
    - why: keep recovery disablement consistent across all maintained backends
    - coverage: `advArchiver/tests/test_cli_contract.py::TestCliContract.test_all_shared_flags_parse_on_each_subcommand`, `advArchiver/tests/test_rar_backend.py::TestRarBackend.test_rar_no_rec_disables_native_rr`
  - shared `--rec-threads` is parsed for CLI consistency, but inline native recovery still does not consume the separate recovery executor
    - why: keep one shared flag surface without pretending inline RAR recovery is external work
    - coverage: `advArchiver/tests/test_cli_contract.py::TestCliContract.test_shared_argument_surface_exists_on_all_subcommands`, `advArchiver/tests/test_recovery_policies.py::TestRecoveryScheduling.test_inline_recovery_does_not_consume_rec_threads`
  - native recovery-record failures are surfaced as warning data when archive artifacts were created, and warning-only runs exit `3`
    - why: keep archive-success-plus-recovery-failure distinct from hard archive failure in the shared engine
    - coverage: `advArchiver/tests/test_rar_backend.py::TestRarBackend.test_execute_job_surfaces_recovery_record_warning_as_warning_data`, `advArchiver/tests/test_engine_and_models.py::TestEngineLifecycle.test_inline_native_recovery_warning_maps_to_exit_code_three_and_blocks_delete`
- Current tests:
  - `advArchiver/tests/test_rar_backend.py::TestRarBackend.test_rar_default_switches_include_native_rr`
  - `advArchiver/tests/test_rar_backend.py::TestRarBackend.test_rar_no_rec_disables_native_rr`
  - `advArchiver/tests/test_rar_backend.py::TestRarBackend.test_rar_delete_preserves_legacy_df_behavior`
  - `advArchiver/tests/test_rar_backend.py::TestRarBackend.test_rar_delete_stays_in_native_archive_command_during_dry_run`
  - `advArchiver/tests/test_rar_backend.py::TestRarBackend.test_rar_parted_profile_preserves_volume_switch`
  - `advArchiver/tests/test_rar_backend.py::TestRarBackend.test_rar_comments_path_preserves_comment_file_switch`
  - `advArchiver/tests/test_rar_backend.py::TestRarBackend.test_rar_default_recovery_provider_is_native_inline`
  - `advArchiver/tests/test_rar_backend.py::TestRarBackend.test_execute_job_surfaces_recovery_record_warning_as_warning_data`
