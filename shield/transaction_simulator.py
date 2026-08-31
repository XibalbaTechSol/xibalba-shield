"""Read-only EVM simulation for approved Shield transaction intents."""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .transaction_gateway import TransactionIntent


DEFAULT_RPC_URLS = {
    11155111: "https://ethereum-sepolia-rpc.publicnode.com",
    84532: "https://sepolia.base.org",
    5042002: "https://rpc.testnet.arc.network",
}


class SimulationError(RuntimeError):
    """Raised when the chain cannot produce a trustworthy simulation result."""


@dataclass(frozen=True)
class SimulationResult:
    chain_id: int
    rpc_url: str
    gas_estimate: int
    return_data: str
    status: str = "simulated"
    execution: str = "not_broadcast"

    def as_dict(self) -> dict[str, object]:
        return {
            "chain_id": self.chain_id,
            "rpc_url": self.rpc_url,
            "gas_estimate": self.gas_estimate,
            "return_data": self.return_data,
            "status": self.status,
            "execution": self.execution,
        }


class JsonRpcClient:
    def __init__(self, rpc_url: str, *, timeout: float = 5.0):
        if not rpc_url.startswith("https://") and not rpc_url.startswith("http://127.0.0.1"):
            raise ValueError("RPC URL must use HTTPS, except for local test servers")
        self.rpc_url = rpc_url
        self.timeout = timeout

    def call(self, method: str, params: list[object]) -> object:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
        request = Request(self.rpc_url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (OSError, HTTPError, URLError, json.JSONDecodeError) as exc:
            raise SimulationError(f"RPC request failed: {exc}") from exc
        if payload.get("error"):
            raise SimulationError(f"RPC {method} failed: {payload['error']}")
        if "result" not in payload:
            raise SimulationError(f"RPC {method} returned no result")
        return payload["result"]


def _hex_quantity(value: int) -> str:
    return hex(value)


def simulate_transaction_intent(
    intent: TransactionIntent,
    *,
    rpc_url: str | None = None,
    timeout: float = 5.0,
) -> SimulationResult:
    """Run eth_call and eth_estimateGas; never invokes a write RPC method."""
    intent.validate()
    if not intent.calldata:
        raise SimulationError("calldata is required for simulation")
    url = rpc_url or DEFAULT_RPC_URLS.get(intent.chain_id)
    if not url:
        raise SimulationError(f"no trusted RPC configured for chain {intent.chain_id}")
    client = JsonRpcClient(url, timeout=timeout)
    tx: dict[str, str] = {
        "to": intent.to,
        "data": intent.calldata,
        "value": _hex_quantity(intent.value_wei),
    }
    if intent.sender:
        tx["from"] = intent.sender
    return_data = client.call("eth_call", [tx, "latest"])
    gas = client.call("eth_estimateGas", [tx])
    if not isinstance(return_data, str) or not isinstance(gas, str) or not gas.startswith("0x"):
        raise SimulationError("RPC returned malformed simulation data")
    try:
        gas_estimate = int(gas, 16)
    except ValueError as exc:
        raise SimulationError("RPC returned invalid gas estimate") from exc
    return SimulationResult(intent.chain_id, url, gas_estimate, return_data)


__all__ = ["DEFAULT_RPC_URLS", "JsonRpcClient", "SimulationError", "SimulationResult", "simulate_transaction_intent"]
