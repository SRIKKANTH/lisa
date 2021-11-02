# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from assertpy.assertpy import assert_that
from lisa.executable import Tool
from lisa.operating_system import Posix
from lisa.tools.lscpu import Lscpu
from lisa.tools.lsmod import Lsmod


class Qemu(Tool):
    @property
    def command(self) -> str:
        return "qemu-system-x86_64"

    def _install(self) -> bool:
        assert isinstance(self.node.os, Posix)
        is_virtualization_enabled = self.node.tools[Lscpu].is_virtualization_enabled()
        assert_that(is_virtualization_enabled, "Virtualization is disabled").is_true()
        self.node.os.install_packages("qemu-kvm")
        self.node.os.install_packages("bridge-utils")
        self._is_kvm_successfully_enabled()
        self.node.os.install_packages("dnsmasq")

    def _is_kvm_successfully_enabled(self) -> None:
        lsmod_output = self.node.tools[Lsmod].run()
        is_kvm_successfully_enabled = "kvm_intel" in lsmod_output
        assert_that(
            is_kvm_successfully_enabled, f"KVM could not be enabled : {lsmod_output}"
        ).is_true()

    def start_vm(self) -> None:
        self.run(
            "-smp 2 -m 2048 -hda ~/image.qcow2 -display none -device e1000,netdev=user.0 -netdev user,id=user.0,hostfwd=tcp::60022-:22 -enable-kvm -daemonize"
        )
