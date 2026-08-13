package shield.policy

import rego.v1

default allow := false

default action := "log_only"

default message := "no policy rule matched"

default rule_id := "_no_match"

default name := "No rule matched"

default version := "0"

default requires_baa := false

ps_rule_1 if {
	input.event.agent != null
	not input.ctx.registered_agent_ids[input.event.agent.agent_id]
}

ps_rule_2 if {
	input.event.context != null
	glob.match("https://unapproved.example/*", [], input.event.context.model_endpoint)
}

ps_rule_2 if {
	input.event.context != null
	glob.match("http://*", [], input.event.context.model_endpoint)
}

ps_rule_3 if {
	input.event.context != null
	source := input.event.context.data_sources[_]
	source in {"client_contracts", "customer_records", "financial_docs"}
}

allow if ps_rule_1
allow if ps_rule_2
allow if ps_rule_3

action := "deny" if ps_rule_1

action := "deny" if {
	not ps_rule_1
	ps_rule_2
}

action := "escalate" if {
	not ps_rule_1
	not ps_rule_2
	ps_rule_3
}

message := "Unregistered agent activity denied." if ps_rule_1

message := "Model endpoint is not approved for this tenant." if {
	not ps_rule_1
	ps_rule_2
}

message := "Client data source attached to agent context." if {
	not ps_rule_1
	not ps_rule_2
	ps_rule_3
}

rule_id := "ps-deny-unregistered-agents" if ps_rule_1

rule_id := "ps-deny-unapproved-model-routing" if {
	not ps_rule_1
	ps_rule_2
}

rule_id := "ps-escalate-client-data-context" if {
	not ps_rule_1
	not ps_rule_2
	ps_rule_3
}

name := "Deny unregistered agent activity" if ps_rule_1

name := "Deny unapproved model endpoints" if {
	not ps_rule_1
	ps_rule_2
}

name := "Escalate client-data context attachment" if {
	not ps_rule_1
	not ps_rule_2
	ps_rule_3
}

version := "1.0.0" if ps_rule_1
version := "1.0.0" if ps_rule_2
version := "1.0.0" if ps_rule_3
