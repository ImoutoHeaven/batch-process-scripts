class RecoveryProviderBase:
    uses_recovery_executor = True

    def check_required_tools(self, args):
        raise NotImplementedError

    def apply(self, job, execution_result, args):
        raise NotImplementedError
