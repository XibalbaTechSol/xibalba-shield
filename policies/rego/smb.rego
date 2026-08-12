package shield.policy

default allow = false
default action = "log_only"
default message = "no policy rule matched"
default rule_id = "_no_match"
default name = "No rule matched"
default version = "0"
default requires_baa = false

match_glob_array(val, patterns) {
    some i
    glob.match(patterns[i], [], val)
}

rule_1 {
    input.event.process != null
    match_glob_array(input.event.process.exe_path, ["*/ai/*", "*/llm-tools/*", "*/shadow-agent/*"])
}

rule_2 {
    input.event.agent != null
    input.ctx.registered_agent_ids[input.event.agent.agent_id] == false
}

rule_3 {
    input.event.file != null
    match_glob_array(input.event.file.path, ["/home/*/.ssh/*", "/etc/*", "/var/secrets/*"])
}

allow = true { rule_1 }
allow = true { rule_2 }
allow = true { rule_3 }

action = "contain" { rule_1 }
action = "deny" { rule_2 }
action = "escalate" { rule_3 }

message = "Unregistered AI workload path contained." { rule_1 }
message = "Agent is not registered on this endpoint." { rule_2 }
message = "Sensitive path write observed." { rule_3 }

rule_id = "smb-contain-shadow-ai-processes" { rule_1 }
rule_id = "smb-deny-unregistered-agent-tools" { rule_2 }
rule_id = "smb-escalate-sensitive-file-write" { rule_3 }

name = "Contain known shadow AI process paths" { rule_1 }
name = "Deny unregistered agent tool activity" { rule_2 }
name = "Escalate sensitive file write metadata" { rule_3 }

version = "1.0.0" { rule_1 }
version = "1.0.0" { rule_2 }
version = "1.0.0" { rule_3 }
