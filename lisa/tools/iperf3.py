# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from typing import Any, List, Type, cast

from lisa.executable import Tool
from lisa.operating_system import Posix

from .git import Git
from .make import Make


class Iperf3(Tool):
    repo = "https://github.com/esnet/iperf"
    branch = "3.10.1"

    @property
    def command(self) -> str:
        return self._command

    @property
    def can_install(self) -> bool:
        return True

    @property
    def dependencies(self) -> List[Type[Tool]]:
        return [Git, Make]

    def _initialize(self, *args: Any, **kwargs: Any) -> None:
        self._command = "iperf3"

    def _install_from_src(self) -> None:
        tool_path = self.get_tool_path()
        git = self.node.tools[Git]
        git.clone(self.repo, tool_path)
        code_path = tool_path.joinpath("iperf")
        make = self.node.tools[Make]
        make.make_install(code_path)
        self._command = "/usr/local/bin/iperf3"

    def install(self) -> bool:
        posix_os: Posix = cast(Posix, self.node.os)
        posix_os.install_packages("iperf3")
        if not self._check_exists():
            self._install_from_src()
        return self._check_exists()

    def run_as_server(self, daemon: bool = True) -> None:
        # -s: run iperf3 as server mode
        # -D: run iperf3 as a daemon
        cmd = "-s"
        if daemon:
            cmd += " -D"
        self.run(
            cmd,
            force_run=True,
            shell=True,
            expected_exit_code=0,
            expected_exit_code_failure_message=f"fail to launch cmd {self._command}"
            f"{cmd}",
        )

    def run_as_client(
        self,
        server_ip: str,
        log_file: str = "",
        seconds: int = 10,
        run_in_bg: bool = False,
    ) -> None:
        # -c: run iperf3 as client mode, followed by iperf3 server ip address
        # -t: run iperf3 testing for given seconds
        # --logfile: save logs into specified file
        cmd = f"-t {seconds} -c {server_ip}"
        if log_file:
            self.node.shell.remove(self.node.get_pure_path(log_file))
            cmd += f" --logfile {log_file}"
        if run_in_bg:
            self.node.execute_async(
                f"{self._command} {cmd}", shell=True, sudo=self._use_sudo
            )
        else:
            self.run(
                cmd,
                force_run=True,
                shell=True,
                expected_exit_code=0,
                expected_exit_code_failure_message=f"fail to launch cmd {self._command}"
                f"{cmd}",
            )
