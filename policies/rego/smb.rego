package shield.policy

import rego.v1

default allow := false

default action := "log_only"

default message := "no policy rule matched"

default rule_id := "_no_match"

default name := "No rule matched"

default version := "0"

default requires_baa := false

match_glob_array(val, patterns) if {
	some i
	glob.match(patterns[i], [], val)
}

rule_1 if {
	input.event.process != null
	match_glob_array(input.event.process.exe_path, ["*/ai/*", "*/llm-tools/*", "*/shadow-agent/*"])
}

rule_2 if {
	input.event.agent != null
	not input.ctx.registered_agent_ids[input.event.agent.agent_id]
}

rule_3 if {
	input.event.file != null
	match_glob_array(input.event.file.path, ["/home/*/.ssh/*", "/etc/*", "/var/secrets/*"])
}

allow if rule_1
allow if rule_2
allow if rule_3

action := "contain" if rule_1

action := "deny" if {
	not rule_1
	rule_2
}

action := "escalate" if {
	not rule_1
	not rule_2
	rule_3
}

message := "Unregistered AI workload path contained." if rule_1

message := "Agent is not registered on this endpoint." if {
	not rule_1
	rule_2
}

message := "Sensitive path write observed." if {
	not rule_1
	not rule_2
	rule_3
}

rule_id := "smb-contain-shadow-ai-processes" if rule_1

rule_id := "smb-deny-unregistered-agent-tools" if {
	not rule_1
	rule_2
}

rule_id := "smb-escalate-sensitive-file-write" if {
	not rule_1
	not rule_2
	rule_3
}

name := "Contain known shadow AI process paths" if rule_1

name := "Deny unregistered agent tool activity" if {
	not rule_1
	rule_2
}

name := "Escalate sensitive file write metadata" if {
	not rule_1
	not rule_2
	rule_3
}

version := "1.0.0" if rule_1
version := "1.0.0" if rule_2
version := "1.0.0" if rule_3
