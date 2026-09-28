package shield.policy

import rego.v1

# The default bundle is selected by the OPA process that loads this file. Each
# file is intentionally checked independently; loading multiple verticals into
# one package would create conflicting default rules.
default allow := true

default action := "log_only"

default message := "no policy rule matched"

default rule_id := "_no_match"

default name := "No rule matched"

default version := "0"

default requires_baa := false

regulated_rule_1 if {
	input.event.agent != null
	not input.ctx.registered_agent_ids[input.event.agent.agent_id]
}

regulated_rule_2 if {
	input.event.context != null
	source := input.event.context.data_sources[_]
	source in {"ehr_encounter", "patient_record", "claims_phi"}
}

regulated_rule_3 if {
	input.event.activity != null
	input.event.activity.risk_level in {"high", "critical"}
}

regulated_rule_4 if {
	input.event.file != null
	glob.match("/home/*/.ssh/*", [], input.event.file.path)
}

regulated_rule_4 if {
	input.event.file != null
	glob.match("/etc/*", [], input.event.file.path)
}

regulated_rule_4 if {
	input.event.file != null
	glob.match("/var/lib/*/secrets/*", [], input.event.file.path)
}

regulated_rule_4 if {
	input.event.file != null
	glob.match("/var/secrets/**", [], input.event.file.path)
}

allow if regulated_rule_1
allow if regulated_rule_2
allow if regulated_rule_3
allow if regulated_rule_4

action := "deny" if regulated_rule_1

action := "deny" if {
	not regulated_rule_1
	regulated_rule_2
}

action := "deny" if {
	not regulated_rule_1
	not regulated_rule_2
	regulated_rule_3
}

action := "escalate" if {
	not regulated_rule_1
	not regulated_rule_2
	not regulated_rule_3
	regulated_rule_4
}

message := "Unregistered agent activity denied in regulated mode." if regulated_rule_1

message := "PHI-bearing data source cannot be attached to this agent context." if {
	not regulated_rule_1
	regulated_rule_2
}

message := "High-risk output release denied." if {
	not regulated_rule_1
	not regulated_rule_2
	regulated_rule_3
}

message := "Sensitive regulated path write observed." if {
	not regulated_rule_1
	not regulated_rule_2
	not regulated_rule_3
	regulated_rule_4
}

rule_id := "regulated-deny-unregistered-agents" if regulated_rule_1

rule_id := "regulated-deny-phi-context" if {
	not regulated_rule_1
	regulated_rule_2
}

rule_id := "regulated-deny-high-risk-output" if {
	not regulated_rule_1
	not regulated_rule_2
	regulated_rule_3
}

rule_id := "regulated-escalate-sensitive-write" if {
	not regulated_rule_1
	not regulated_rule_2
	not regulated_rule_3
	regulated_rule_4
}

name := "Deny unregistered agent activity" if regulated_rule_1

name := "Deny PHI-bearing data-source context" if {
	not regulated_rule_1
	regulated_rule_2
}

name := "Deny high-risk output release" if {
	not regulated_rule_1
	not regulated_rule_2
	regulated_rule_3
}

name := "Escalate regulated sensitive-path writes" if {
	not regulated_rule_1
	not regulated_rule_2
	not regulated_rule_3
	regulated_rule_4
}

version := "1.0.0" if regulated_rule_1
version := "1.0.0" if regulated_rule_2
version := "1.0.0" if regulated_rule_3
version := "1.0.0" if regulated_rule_4

# See shield/policies/rego/smb.rego's matching comment: `decision`/`reason_code` carry the
# C3 decision contract (integrity_sdk.core.decision), deliberately undefined (no default)
# on no-match so `core.decision.resolve()` applies this pack's own per-event-class default
# -- this profile is the one that declares `agent_event` deny-by-default (docs/EXECUTION_PLAN.md
# A3: "hipaa agent tool calls deny").
decision := "deny" if regulated_rule_1

decision := "deny" if {
	not regulated_rule_1
	regulated_rule_2
}

decision := "deny" if {
	not regulated_rule_1
	not regulated_rule_2
	regulated_rule_3
}

decision := "deny" if {
	not regulated_rule_1
	not regulated_rule_2
	not regulated_rule_3
	regulated_rule_4
}

reason_code := "REGULATED_DENY_UNREGISTERED_AGENT" if regulated_rule_1

reason_code := "REGULATED_DENY_PHI_CONTEXT" if {
	not regulated_rule_1
	regulated_rule_2
}

reason_code := "REGULATED_DENY_HIGH_RISK_OUTPUT" if {
	not regulated_rule_1
	not regulated_rule_2
	regulated_rule_3
}

reason_code := "REGULATED_ESCALATE_SENSITIVE_WRITE" if {
	not regulated_rule_1
	not regulated_rule_2
	not regulated_rule_3
	regulated_rule_4
}
