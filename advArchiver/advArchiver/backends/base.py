class BackendBase:
    name = ""

    def register_arguments(self, subparser):
        raise NotImplementedError

    def capabilities(self):
        raise NotImplementedError

    def validate_args(self, args):
        raise NotImplementedError

    def check_required_tools(self, args):
        raise NotImplementedError

    def build_job(self, item_path, args, base_path):
        raise NotImplementedError

    def execute_job(self, job, args):
        raise NotImplementedError

    def select_recovery_provider(self, args, execution_result):
        raise NotImplementedError
