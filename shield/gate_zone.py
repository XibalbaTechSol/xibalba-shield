"""The gate's zone mask: a control zone restricts which classes of tool call the gate allows.

Off by default. With `--zone-mode off` (the default) `build_zone_mask` returns None, the daemon holds
no mask and no provider, and `gate_daemon.evaluate_pre_tool_use` takes exactly the path it took before
this module existed.

The loop this closes, locally
-----------------------------
The wider system computes an Agent Integrity Score and a control zone (green / yellow / red). This
module is the *enforcement* half only, and it needs no chain, token or hosted oracle:

    zone provider --(zone for this agent)--> ZoneMask --(may this class of call run?)--> gate

* **Action classes.** A tool name is classified `read | draft | execute | escalate` from a
  configurable map. A tool that is not in the map is `execute`, never `read`: unknown means "could do
  anything". Matching is exact and case-sensitive, so a misspelt known tool is an unknown tool.
* **Zones.** green permits read, draft, execute; yellow permits read, draft; red permits read only.
  `escalate` is permitted in every zone -- a restricted agent must still be able to ask for help.
* **Only ever removes permission.** The mask runs *after* the policy pack has answered and is consulted
  only to turn a permit into a deny. A call the pack denies stays denied in every zone, with the
  pack's own reason. Pack evaluation is not changed and is not given the zone.

The provider seam
-----------------
A zone provider is any callable ``agent_id -> ZoneReading | str``. Returning a bare zone name is
enough. Two ship here:

* `StaticZoneProvider` -- a configured zone, optionally per agent. This is how an operator (or a
  test) sets the zone today.
* `SensorSilenceZoneProvider` -- wraps another provider and caps its answer when Shield's own sensor
  has gone quiet (below).
* `AisReceiptZoneProvider` (`--zone-provider ais`) -- the zone this gate's own receipts imply, scored
  by `integrity_sdk.core.ais_local`. This closes the loop locally: decision -> receipt -> score -> zone
  -> mask, with no chain, token or Oracle. Needs `--receipt-dir` and an explicit `ais.default_tier`.

This module does not compute a score itself. Another scorer plugs in by registering a factory
(`register_zone_provider(name, factory)`) or by being named by import path
(`--zone-provider package.module:factory`); `build_zone_mask` wraps whatever it returns in the silence
wrapper. Neither `gate_daemon.py` nor this module's mask changes.

Anything a provider gets wrong is `unknown`, never green: an exception, or an answer that is not a
zone name. What `unknown` means is one setting (`unknown_as`, default yellow).

Sensor silence is a fault
-------------------------
Without this, the cheapest way for an agent to shed scrutiny is to stop the sensor: no observations,
no evidence, no demotion. `SensorSilenceZoneProvider` reads the status file the watchdog writes
(`shield.sensor_status`, `shield run --sensor-status-file`) on every decision and reports one of:

==================  ========================================================  ==========
state               meaning                                                   demotes?
==================  ========================================================  ==========
``not_configured``  no status file was configured: this gate runs standalone  no
``fresh``           written within `max_age_seconds`, sensor says attached    no
``stale``           well-formed, but older than `max_age_seconds`             yes
``unhealthy``       fresh, but `sensors.attached` is not true, or has `error`  yes
``missing``         a sensor is expected and there is no file                 yes
``unreadable``      the file cannot be read, parsed, or is dated in the future yes
``never_seen``      `expect="when-seen"` and the file has never existed       no
==================  ========================================================  ==========

"Never had a sensor" and "the sensor went silent" are therefore different states. A gate with no
status file configured is never demoted. Configuring one is the statement that a sensor is expected,
and from then on (`expect="always"`, the default) a missing or unreadable file is silence, not health.
`expect="when-seen"` excuses a file that has never existed since this daemon started -- for bringing a
gate up before its sensor -- and nothing else.

Demotion is a *ceiling* (red by default, yellow if configured) on the wrapped provider's zone: it can
lower a zone and can never raise one.

Receipts
--------
The receipt format (`integrity_sdk.core.receipts`, SDK contract C4) has a closed field set, checked
by both the SDK and `integrity-cli`'s independent verifier, so a receipt cannot grow a `zone` field
without a new receipt version. `reason_code` and `controls` are open, so the zone and class are
recorded there: a masked call is ``decision: deny, reason_code: AIS_ZONE_RESTRICTED`` and every
receipt written while the mask is on carries the controls ``ais_zone:<zone>``,
``ais_action_class:<class>`` and ``ais_zone_source:<source>`` (shadow mode adds
``ais_zone_mask:shadow_restricted`` to a call it would have blocked). Existing verifiers accept these
unchanged.
"""

from __future__ import annotations

import importlib
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence, Union

from .sensor_status import SensorStatusError, read_sensor_status

logger = logging.getLogger(__name__)

GREEN, YELLOW, RED = "green", "yellow", "red"
UNKNOWN = "unknown"
#: Least to most restricted. Order is load-bearing: "the worse of two zones" is the later one.
ZONES = (GREEN, YELLOW, RED)

READ, DRAFT, EXECUTE, ESCALATE = "read", "draft", "execute", "escalate"
ACTION_CLASSES = (READ, DRAFT, EXECUTE, ESCALATE)

MODE_OFF, MODE_SHADOW, MODE_ENFORCE = "off", "shadow", "enforce"
ZONE_MODES = (MODE_OFF, MODE_SHADOW, MODE_ENFORCE)

#: What a tool not named in the map is. Never `read`.
DEFAULT_ACTION_CLASS = EXECUTE

#: The common agent-harness tools. Deliberately short: anything absent is `execute`.
DEFAULT_TOOL_CLASSES: Mapping[str, str] = {
    "Read": READ, "Glob": READ, "Grep": READ,
    "Write": DRAFT, "Edit": DRAFT, "NotebookEdit": DRAFT,
    "Bash": EXECUTE,
}

#: `escalate` is in every row on purpose.
ZONE_PERMITTED_CLASSES: Mapping[str, frozenset[str]] = {
    GREEN: frozenset({READ, DRAFT, EXECUTE, ESCALATE}),
    YELLOW: frozenset({READ, DRAFT, ESCALATE}),
    RED: frozenset({READ, ESCALATE}),
}

#: Reason code (and the start of the human-readable reason) for a call the mask denied. Not in the
#: `INTEGRITY_` namespace the SDK reserves for the decision contract's own outcomes.
REASON_ZONE_RESTRICTED = "AIS_ZONE_RESTRICTED"
RULE_ID_ZONE_MASK = "_ais_zone_mask"

SOURCE_PROVIDER = "provider"
SOURCE_UNKNOWN_DEFAULT = "unknown_default"
SOURCE_PROVIDER_ERROR = "provider_error"
SOURCE_SENSOR_SILENT = "sensor_silent"

SENSOR_NOT_CONFIGURED = "not_configured"
SENSOR_FRESH = "fresh"
SENSOR_STALE = "stale"
SENSOR_UNHEALTHY = "unhealthy"
SENSOR_MISSING = "missing"
SENSOR_UNREADABLE = "unreadable"
SENSOR_NEVER_SEEN = "never_seen"
#: The states in which the sensor is taken to be working, or was never part of this deployment.
SENSOR_STATES_NOT_SILENT = frozenset({SENSOR_NOT_CONFIGURED, SENSOR_FRESH, SENSOR_NEVER_SEEN})

EXPECT_ALWAYS, EXPECT_WHEN_SEEN = "always", "when-seen"
SENSOR_EXPECTATIONS = (EXPECT_ALWAYS, EXPECT_WHEN_SEEN)
DEMOTION_ZONES = (RED, YELLOW)

#: Four default watchdog ticks (`shield run --watchdog-interval`, 15 s): one slow tick is not silence.
DEFAULT_SENSOR_MAX_AGE_SECONDS = 60.0
#: How far ahead of this process's clock a status may be dated before it is refused.
MAX_FUTURE_SKEW_SECONDS = 5.0


def worse_zone(first: str, second: str) -> str:
    """The more restricted of two (known) zones."""
    return first if ZONES.index(first) >= ZONES.index(second) else second


def classify_tool(tool_name: str, tool_classes: Mapping[str, str] = DEFAULT_TOOL_CLASSES) -> str:
    """`tool_name`'s action class under `tool_classes`; `execute` if it is not listed."""
    return tool_classes.get(tool_name, DEFAULT_ACTION_CLASS)


@dataclass(frozen=True)
class ZoneReading:
    """A provider's answer for one agent.

    `zone` is a zone name or `unknown`. `ceiling`, when set, is a zone the effective zone may not be
    better than -- how a wrapper demotes without needing to know what `unknown` resolves to.
    `source` and `sensor` are carried into the response and the receipt so "why was this red?" has an
    answer.
    """

    zone: str
    source: str = SOURCE_PROVIDER
    ceiling: Optional[str] = None
    sensor: Optional[str] = None


#: The seam. Returning a bare zone name is enough; `ZoneReading` is for providers with more to say.
ZoneProvider = Callable[[str], Union[ZoneReading, str]]


def _as_reading(answer: Any) -> ZoneReading:
    """Coerce a provider's answer. Anything that is not a zone is `unknown` -- never green."""
    if isinstance(answer, ZoneReading):
        zone = answer.zone if isinstance(answer.zone, str) and answer.zone in ZONES else UNKNOWN
        ceiling = answer.ceiling if isinstance(answer.ceiling, str) and answer.ceiling in ZONES else None
        if answer.ceiling is not None and ceiling is None:
            # A ceiling that is not a zone is a broken demotion; the safe reading of it is the lowest.
            ceiling = RED
        return ZoneReading(zone=zone, source=answer.source, ceiling=ceiling, sensor=answer.sensor)
    if isinstance(answer, str) and answer in ZONES:
        return ZoneReading(zone=answer)
    return ZoneReading(zone=UNKNOWN)


class StaticZoneProvider:
    """A configured zone: `default` for everyone, with optional per-agent overrides."""

    def __init__(self, default: str = UNKNOWN, per_agent: Optional[Mapping[str, str]] = None) -> None:
        for label, zone in (("default", default), *(per_agent or {}).items()):
            if zone not in ZONES and zone != UNKNOWN:
                raise ValueError(f"zone for {label!r} must be one of {ZONES} or {UNKNOWN!r}, got {zone!r}")
        self._default = default
        self._per_agent = dict(per_agent or {})

    def __call__(self, agent_id: str) -> ZoneReading:
        return ZoneReading(zone=self._per_agent.get(agent_id, self._default))


class SensorSilenceZoneProvider:
    """Caps another provider's zone while Shield's sensor is silent. See the module docstring."""

    def __init__(
        self,
        inner: ZoneProvider,
        *,
        status_path: Optional[Path | str],
        max_age_seconds: float = DEFAULT_SENSOR_MAX_AGE_SECONDS,
        demote_to: str = RED,
        expect: str = EXPECT_ALWAYS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if demote_to not in DEMOTION_ZONES:
            raise ValueError(f"sensor demotion zone must be one of {DEMOTION_ZONES}, got {demote_to!r}")
        if expect not in SENSOR_EXPECTATIONS:
            raise ValueError(f"sensor expectation must be one of {SENSOR_EXPECTATIONS}, got {expect!r}")
        if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, (int, float)) or max_age_seconds <= 0:
            raise ValueError(f"sensor max age must be a positive number of seconds, got {max_age_seconds!r}")
        self._inner = inner
        self._status_path = Path(status_path) if status_path is not None else None
        self._max_age = float(max_age_seconds)
        self._demote_to = demote_to
        self._expect = expect
        self._clock = clock
        # Only read under `expect="when-seen"`. Set once and never cleared, so a race between two
        # request threads can only set it twice.
        self._seen = False
        self._seen_lock = threading.Lock()

    def sensor_state(self) -> str:
        """Where the sensor stands right now. Never raises."""
        if self._status_path is None:
            return SENSOR_NOT_CONFIGURED
        try:
            status = read_sensor_status(self._status_path)
        except FileNotFoundError:
            if self._expect == EXPECT_WHEN_SEEN and not self._seen:
                return SENSOR_NEVER_SEEN
            return SENSOR_MISSING
        except (OSError, SensorStatusError):
            self._mark_seen()
            return SENSOR_UNREADABLE
        except Exception:  # noqa: BLE001 -- an unexpected failure to read health is not health
            logger.exception("sensor status read failed unexpectedly; treating the sensor as silent")
            self._mark_seen()
            return SENSOR_UNREADABLE
        self._mark_seen()

        now = self._clock()
        written_at = float(status["written_at"])
        if written_at > now + MAX_FUTURE_SKEW_SECONDS:
            return SENSOR_UNREADABLE
        if now - written_at > self._max_age:
            return SENSOR_STALE
        sensors = status["sensors"]
        if sensors.get("attached") is not True or "error" in sensors:
            return SENSOR_UNHEALTHY
        return SENSOR_FRESH

    def _mark_seen(self) -> None:
        if not self._seen:
            with self._seen_lock:
                self._seen = True

    def __call__(self, agent_id: str) -> ZoneReading:
        state = self.sensor_state()
        try:
            inner = _as_reading(self._inner(agent_id))
        except Exception:  # noqa: BLE001 -- the silence verdict must survive a broken inner provider
            logger.exception("zone provider raised; treating the zone as unknown")
            inner = ZoneReading(zone=UNKNOWN, source=SOURCE_PROVIDER_ERROR)
        if state in SENSOR_STATES_NOT_SILENT:
            return ZoneReading(zone=inner.zone, source=inner.source, ceiling=inner.ceiling, sensor=state)
        ceiling = self._demote_to if inner.ceiling is None else worse_zone(inner.ceiling, self._demote_to)
        return ZoneReading(zone=inner.zone, source=SOURCE_SENSOR_SILENT, ceiling=ceiling, sensor=state)


@dataclass(frozen=True)
class ZoneAssessment:
    """What the mask concluded about one call. `restricted` is the mask's own verdict, independent of
    what the policy pack said; whether it changed the outcome is the gate's `applied`."""

    zone: str
    action_class: str
    restricted: bool
    source: str
    sensor: Optional[str]


class ZoneMask:
    """Classifies a tool call and says whether the agent's current zone permits that class."""

    def __init__(
        self,
        *,
        mode: str,
        provider: ZoneProvider,
        tool_classes: Optional[Mapping[str, str]] = None,
        unknown_zone: str = YELLOW,
        entitlement: Optional[Callable[[], str]] = None,
    ) -> None:
        """`entitlement` returns a `shield.entitlement` status; anything but `ok` runs `enforce` as
        `shadow`. None leaves `enforce` ungated -- for embedding and unit tests only:
        `build_zone_mask`, the path every daemon takes, always attaches one."""
        if mode not in ZONE_MODES:
            raise ValueError(f"zone mode must be one of {ZONE_MODES}, got {mode!r}")
        if unknown_zone not in ZONES:
            raise ValueError(f"the zone an unknown zone is treated as must be one of {ZONES}, got {unknown_zone!r}")
        merged = dict(DEFAULT_TOOL_CLASSES)
        merged.update(tool_classes or {})
        for tool, action_class in merged.items():
            if action_class not in ACTION_CLASSES:
                raise ValueError(
                    f"action class for tool {tool!r} must be one of {ACTION_CLASSES}, got {action_class!r}")
        self.mode = mode
        self._provider = provider
        self._tool_classes = merged
        self._unknown_zone = unknown_zone
        self._entitlement = entitlement

    def effective_mode(self) -> tuple[str, Optional[str]]:
        """(the mode actually applied, the entitlement status or None when none was consulted).

        Only a requested `enforce` consults the entitlement. Without a valid one it runs as `shadow`
        -- observing, never blocking (design §1/§6: billing is never in the decision path). Never raises.
        """
        if self.mode != MODE_ENFORCE or self._entitlement is None:
            return self.mode, None
        try:
            status = self._entitlement()
        except Exception:  # noqa: BLE001
            logger.exception("entitlement check raised; zone enforce runs as shadow")
            status = "malformed"
        return (MODE_ENFORCE if status == "ok" else MODE_SHADOW), status

    @property
    def active(self) -> bool:
        """False for `off`: the gate must not consult the mask, or its provider, at all."""
        return self.mode != MODE_OFF

    def classify(self, tool_name: str) -> str:
        return classify_tool(tool_name, self._tool_classes)

    def assess(self, agent_id: str, tool_name: str) -> ZoneAssessment:
        """Never raises: a provider failure is an unknown zone, not an open gate or a crashed one."""
        try:
            reading = _as_reading(self._provider(agent_id))
        except Exception:  # noqa: BLE001
            logger.exception("zone provider raised; treating the zone as unknown")
            reading = ZoneReading(zone=UNKNOWN, source=SOURCE_PROVIDER_ERROR)

        zone, source = reading.zone, reading.source
        if zone == UNKNOWN:
            zone = self._unknown_zone
            if source == SOURCE_PROVIDER:
                source = SOURCE_UNKNOWN_DEFAULT
        if reading.ceiling is not None:
            zone = worse_zone(zone, reading.ceiling)
        action_class = self.classify(tool_name)
        return ZoneAssessment(
            zone=zone, action_class=action_class,
            restricted=action_class not in ZONE_PERMITTED_CLASSES[zone],
            source=source, sensor=reading.sensor,
        )


# --------------------------------------------------------------------------- ais provider ---

PROVIDER_AIS = "ais"
#: `ZoneReading.source` for a zone the local scorer computed, and for its cold start (no score yet).
SOURCE_AIS_LOCAL = "ais_local"
SOURCE_AIS_COLD_START = "ais_local_cold_start"
#: `gate_zone.ais` fields, passed to `integrity_sdk.core.ais_local.LocalScorerSettings`
#: (`zone_policy` through `ZonePolicy.from_mapping`).
AIS_SETTING_FIELDS = frozenset({
    "default_tier", "agent_tiers", "window_size", "min_observations", "max_age_seconds", "zone_policy",
})


class AisReceiptZoneProvider:
    """The zone the gate's own receipts imply for an agent: the AIS loop closed on this device.

    Wraps `integrity_sdk.core.ais_local.ReceiptLogZoneSource`, which tails the receipts file this gate
    writes and scores each agent's recent pack decisions (profile `ais-local/receipts-compliance-1`).
    No Oracle, chain or token is consulted. The mask's own denials are not counted by the scorer, so a
    red zone cannot keep itself red; an agent with too little history is `unknown` (`unknown_as`), never
    a computed red. A scorer failure is an exception here, which the mask already turns into `unknown`.
    """

    def __init__(self, source: Callable[[str], Any]) -> None:
        self._source = source

    def __call__(self, agent_id: str) -> ZoneReading:
        score = self._source(agent_id)
        if score.ais is None:
            return ZoneReading(zone=UNKNOWN, source=SOURCE_AIS_COLD_START)
        return ZoneReading(zone=score.zone, source=SOURCE_AIS_LOCAL)


def _ais_scorer_settings(options: Mapping[str, Any]):
    from integrity_sdk.core.ais_local import LocalScorerSettings
    from integrity_sdk.core.ais_reward import ZonePolicy

    _require("default_tier" in options,
             "the ais zone provider needs ais.default_tier (0-3): the verification tier is never assumed")
    kwargs = {key: value for key, value in options.items() if key != "zone_policy"}
    if "zone_policy" in options:
        policy = options["zone_policy"]
        _require(isinstance(policy, Mapping), "ais.zone_policy must be an object")
        kwargs["zone_policy"] = ZonePolicy.from_mapping(policy)
    return LocalScorerSettings(**kwargs)


def _ais_factory(settings: "GateZoneSettings") -> ZoneProvider:
    from integrity_sdk.core.ais_local import ReceiptLogZoneSource

    _require(settings.receipts_file is not None,
             "the ais zone provider scores this gate's own receipts; it needs receipts (--receipt-dir)")
    return AisReceiptZoneProvider(ReceiptLogZoneSource(settings.receipts_file, _ais_scorer_settings(settings.ais)))


# --------------------------------------------------------------------------- settings ---


@dataclass(frozen=True)
class GateZoneSettings:
    """The `gate_zone` object of a device config, and the `--zone-*` flags of `shield gate-daemon`.

    Every field's default is the feature being off or the documented default, so `GateZoneSettings()`
    is today's behavior.
    """

    mode: str = MODE_OFF
    #: The static provider's zone for every agent; None leaves it `unknown`.
    zone: Optional[str] = None
    agent_zones: Mapping[str, str] = field(default_factory=dict)
    unknown_as: str = YELLOW
    tool_classes: Mapping[str, str] = field(default_factory=dict)
    provider: str = "static"
    #: Configuring this is what says "a sensor is expected". None: this gate runs standalone.
    sensor_status_file: Optional[str] = None
    sensor_max_age_seconds: float = DEFAULT_SENSOR_MAX_AGE_SECONDS
    sensor_demote_to: str = RED
    sensor_expect: str = EXPECT_ALWAYS
    #: The `ais` provider's options (`AIS_SETTING_FIELDS`). Refused for any other provider.
    ais: Mapping[str, Any] = field(default_factory=dict)
    #: The receipts file the `ais` provider scores. The CLI fills it from `--receipt-dir`.
    receipts_file: Optional[str] = None
    #: The signed entitlement (`shield.entitlement`) that `enforce` requires; without a valid one,
    #: `enforce` runs as `shadow`. `entitlement_keys` are the trusted signer public keys (base64).
    entitlement_file: Optional[str] = None
    entitlement_keys: Sequence[str] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _require(self.mode in ZONE_MODES, f"mode must be one of {ZONE_MODES}, got {self.mode!r}")
        _require(self.zone is None or self.zone in ZONES, f"zone must be one of {ZONES}, got {self.zone!r}")
        _require(isinstance(self.agent_zones, Mapping), "agent_zones must be an object of agent_id -> zone")
        for agent_id, zone in self.agent_zones.items():
            _require(isinstance(agent_id, str) and bool(agent_id) and zone in ZONES,
                     f"agent_zones[{agent_id!r}] must be one of {ZONES}, got {zone!r}")
        _require(self.unknown_as in ZONES, f"unknown_as must be one of {ZONES}, got {self.unknown_as!r}")
        _require(isinstance(self.tool_classes, Mapping), "tool_classes must be an object of tool_name -> class")
        for tool, action_class in self.tool_classes.items():
            _require(isinstance(tool, str) and bool(tool) and action_class in ACTION_CLASSES,
                     f"tool_classes[{tool!r}] must be one of {ACTION_CLASSES}, got {action_class!r}")
        _require(isinstance(self.provider, str) and bool(self.provider), "provider must be a non-empty string")
        _require(self.sensor_status_file is None or (
            isinstance(self.sensor_status_file, str) and bool(self.sensor_status_file)),
            "sensor_status_file must be a path string")
        age = self.sensor_max_age_seconds
        _require(not isinstance(age, bool) and isinstance(age, (int, float)) and age > 0,
                 f"sensor_max_age_seconds must be a positive number, got {age!r}")
        _require(self.sensor_demote_to in DEMOTION_ZONES,
                 f"sensor_demote_to must be one of {DEMOTION_ZONES}, got {self.sensor_demote_to!r}")
        _require(self.sensor_expect in SENSOR_EXPECTATIONS,
                 f"sensor_expect must be one of {SENSOR_EXPECTATIONS}, got {self.sensor_expect!r}")
        _require(isinstance(self.ais, Mapping), "ais must be an object")
        unknown_ais = set(self.ais) - AIS_SETTING_FIELDS
        _require(not unknown_ais, f"ais has unknown field(s): {sorted(unknown_ais)}")
        _require(not self.ais or self.provider == PROVIDER_AIS,
                 f"ais options are only read by the {PROVIDER_AIS!r} zone provider, but the provider is {self.provider!r}")
        _require(self.receipts_file is None or (isinstance(self.receipts_file, str) and bool(self.receipts_file)),
                 "receipts_file must be a path string")
        _require(self.entitlement_file is None or (
            isinstance(self.entitlement_file, str) and bool(self.entitlement_file)),
            "entitlement_file must be a path string")
        _require(not isinstance(self.entitlement_keys, (str, bytes)) and all(
            isinstance(key, str) and key for key in self.entitlement_keys),
            "entitlement_keys must be a list of base64 public keys")

    @classmethod
    def from_mapping(cls, document: Mapping[str, Any]) -> "GateZoneSettings":
        """Build from a device config's `gate_zone` object. Raises `ValueError` naming the problem."""
        _require(isinstance(document, Mapping), "gate_zone must be an object")
        known = set(cls.__dataclass_fields__)
        unknown = set(document) - known
        _require(not unknown, f"gate_zone has unknown field(s): {sorted(unknown)}")
        return cls(**dict(document))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


ZoneProviderFactory = Callable[[GateZoneSettings], ZoneProvider]


def _static_factory(settings: GateZoneSettings) -> ZoneProvider:
    return StaticZoneProvider(settings.zone or UNKNOWN, per_agent=settings.agent_zones)


_PROVIDER_FACTORIES: dict[str, ZoneProviderFactory] = {"static": _static_factory, PROVIDER_AIS: _ais_factory}


def register_zone_provider(name: str, factory: ZoneProviderFactory) -> None:
    """Make `factory` selectable as `--zone-provider NAME` / `gate_zone.provider`.

    This is where a real scorer attaches: it registers a factory that returns an
    ``agent_id -> zone`` callable, and the gate never learns it changed.
    """
    if not name or ":" in name:
        raise ValueError("a zone provider name must be non-empty and must not contain ':'")
    _PROVIDER_FACTORIES[name] = factory


def _resolve_provider_factory(name: str) -> ZoneProviderFactory:
    if name in _PROVIDER_FACTORIES:
        return _PROVIDER_FACTORIES[name]
    if ":" in name:
        module_name, _, attribute = name.partition(":")
        try:
            factory = getattr(importlib.import_module(module_name), attribute)
        except (ImportError, AttributeError, ValueError) as exc:
            raise ValueError(f"cannot load zone provider {name!r}: {exc}") from exc
        if not callable(factory):
            raise ValueError(f"zone provider {name!r} is not callable")
        return factory
    raise ValueError(
        f"unknown zone provider {name!r}; registered: {sorted(_PROVIDER_FACTORIES)}, "
        "or name one by import path as 'package.module:factory'"
    )


def build_zone_mask(
    settings: GateZoneSettings, *, tenant_id: str = "", device_id: str = "",
) -> Optional[ZoneMask]:
    """The mask `settings` describes, or None when the mode is `off`.

    None -- rather than a mask that declines to act -- so that an off gate constructs no provider and
    cannot call one. The provider is always wrapped in `SensorSilenceZoneProvider`; with no status
    file configured that wrapper reports `not_configured` and changes nothing.

    The mask always carries an `EntitlementGate` for this tenant and device: `enforce` blocks only
    while a valid signed entitlement says the plan includes it (design §6).
    """
    if settings.mode == MODE_OFF:
        return None
    provider = _resolve_provider_factory(settings.provider)(settings)
    if not callable(provider):
        raise ValueError(f"zone provider {settings.provider!r} did not return a callable")
    wrapped = SensorSilenceZoneProvider(
        provider,
        status_path=settings.sensor_status_file,
        max_age_seconds=settings.sensor_max_age_seconds,
        demote_to=settings.sensor_demote_to,
        expect=settings.sensor_expect,
    )
    from .entitlement import EntitlementGate  # local: keeps `gate_zone` importable without crypto deps

    gate = EntitlementGate(
        settings.entitlement_file, trusted_keys=tuple(settings.entitlement_keys),
        tenant_id=tenant_id, device_id=device_id,
    )
    return ZoneMask(
        mode=settings.mode, provider=wrapped, tool_classes=settings.tool_classes,
        unknown_zone=settings.unknown_as, entitlement=gate.status,
    )
