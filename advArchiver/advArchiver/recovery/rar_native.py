from __future__ import annotations

import importlib

from advArchiver.advArchiver import models

RecoveryProviderBase = importlib.import_module(
    "advArchiver.advArchiver.recovery.base"
).RecoveryProviderBase


class RarNativeRecoveryProvider(RecoveryProviderBase):
    uses_recovery_executor = False

    def check_required_tools(self, args):
        del args

    def apply(self, job, execution_result, args):
        del job, args
        if execution_result.recovery_result is None:
            return models.RecoveryExecutionResult(
                error_msg="RAR native recovery result missing from backend execution",
                command=execution_result.archive_result.command,
                embedded=True,
            )
        return execution_result.recovery_result
