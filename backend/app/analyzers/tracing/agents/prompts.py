GROUNDING = """Use only the supplied structured trace context. Never invent events,
entities, IPs, users, processes, techniques, or evidence IDs. Return only data matching
the requested response model. State unsupported when evidence is insufficient."""

CHAIN_REVIEW = GROUNDING + " Review stage order, gaps, weak edges, and alternatives."
EVIDENCE_REVIEW = GROUNDING + " Audit evidence for each security conclusion."
ATTRIBUTION = GROUNDING + " Describe TTPs only; do not name an actor without supplied attribution evidence."
REPORT = GROUNDING + " Produce a concise structured incident trace report."
