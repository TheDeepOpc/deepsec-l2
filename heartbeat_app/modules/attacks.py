from .base import console


class _UnavailableAttack:
    attack_name = "attack"

    def __init__(self, *args, **kwargs):
        self.available = False

    def _warn(self) -> None:
        console.print(
            f"[yellow]{self.attack_name} is unavailable in this modular build; "
            "skipping related checks.[/yellow]"
        )


class FileUploadAttacker(_UnavailableAttack):
    attack_name = "File upload attacker"

    def attack(self, *args, **kwargs):
        self._warn()
        return []


class JWTAttacker(_UnavailableAttack):
    attack_name = "JWT attacker"

    def attack(self, *args, **kwargs):
        self._warn()
        return []


class WebSocketTester(_UnavailableAttack):
    attack_name = "WebSocket tester"

    def test(self, *args, **kwargs):
        self._warn()
        return []


__all__ = ["FileUploadAttacker", "JWTAttacker", "WebSocketTester"]
