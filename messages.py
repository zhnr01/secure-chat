from dataclasses import dataclass, asdict
import json

@dataclass
class SignedMessage:
    message: str
    r: int
    s: int

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @staticmethod
    def from_json(data: str) -> "SignedMessage":
        obj = json.loads(data)
        return SignedMessage(message=obj["message"], r=obj["r"], s=obj["s"])