# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from lisa.executable import Tool
from lisa.operating_system import Posix


class Aria2c(Tool):
    @property
    def command(self) -> str:
        return "aria2c"

    def _install(self) -> bool:
        assert (self.node.os, Posix)
        self.node.os.install_packages("aria2")

    def download_file(self, url: str, file_name: str, path: str = "~") -> None:
        self.run(f"-d {path} -o {file_name} -x 10 {url}")
