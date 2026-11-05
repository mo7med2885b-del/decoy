"""Agent cards: what each agent on the canvas is, which model it runs on, and its exact system prompt. Read by the UI (/api/agents)."""
from . import agent as agent_mod, debate, investigate, llm
from .config import env
from .swarm import AGENTS

ROLE_OF = {"script": "script", "endpoints": "endpoint", "privacy": "cookies", "lure": "lure"}
CODE_NOTE = "No AI prompt: this agent is plain code (deterministic rules), so it gives the same answer every time."


def _analyst(role: str) -> dict:
    return next(a for a in investigate.ANALYSTS if a["id"] == role)


def cards() -> dict:
    out = {}
    for aid, (name, _icon, kind, what) in AGENTS.items():
        c = {"name": name, "kind": kind, "does": what, "model": None, "prompt": CODE_NOTE}
        if aid in ROLE_OF:
            a = _analyst(ROLE_OF[aid])
            c.update(model=env("DECOY_MODEL_" + aid.upper(), a["model"]), prompt=a["system"] + investigate.FORMAT)
        out[aid] = c
    key = bool(llm.available())
    out["v_careless"] = {"name": "Careless employee", "kind": "model", "does": "A laptop visitor in its own sealed browser. Looks at the page like a slightly careless person and decides each click and which FAKE values to type.",
                         "model": env("DECOY_VISION_MODEL") or env("DECOY_MODEL", "glm-5.3-flash"), "prompt": agent_mod.PLANNER_SYSTEM}
    out["v_phone"] = {"name": "Phone user", "kind": "code", "does": "An iPhone visitor in its own sealed browser. Follows a fixed script (open, look, fill the form, submit).", "model": None, "prompt": CODE_NOTE}
    out["v_bot"] = {"name": "Security bot", "kind": "code", "does": "Looks like a link scanner. If the page shows it something different from the laptop, that is cloaking.", "model": None, "prompt": CODE_NOTE}
    out["debate"] = {"name": "Agent chat room", "kind": "model", "does": "The orchestrator (the most capable model in the swarm) reads every finding, cross-examines agents, and calls a vote; objections trigger another round (at most 3). Agents answer on small flash models. Code finds contradictions, counts the votes and owns the score: a debate can change wording, never the verdict.",
                     "model": env("DECOY_MODEL_ORCH", debate.ORCH_MODEL) + " (orchestrator); agents: flash models",
                     "prompt": "ORCHESTRATOR:\n" + debate.ORCH_SYSTEM + "\n\nANSWERING AGENT:\n" + debate.REPLY_SYSTEM.format(name="<agent name>")}
    out["orch"] = {"name": "Orchestrator", "kind": "model", "does": "The most capable model in the swarm. Every agent reports to it; it cross-examines, calls the vote and starts another round if anyone objects. Code owns the score.",
                    "model": env("DECOY_MODEL_ORCH", debate.ORCH_MODEL), "prompt": debate.ORCH_SYSTEM}
    out["summary"] = {"name": "Summary", "kind": "model", "does": "Writes the plain-words verdict from the facts only; code validates it.", "model": env("DECOY_MODEL", "glm-5.3-flash"), "prompt": agent_mod.SUMMARY_SYSTEM}
    out["analysts"] = {"name": "Analyst team", "kind": "model", "does": "Investigate mode: six analysts, each a different open model, write a report and tag ATT&CK techniques.",
                       "model": ", ".join(sorted({a["model"] for a in investigate.ANALYSTS})),
                       "prompt": "\n\n".join(f"[{a['name']} · {a['model']}]\n{a['system']}" for a in investigate.ANALYSTS)}
    out["_key"] = {"model_key": key}
    return out
