# Agent Governance Toolkit policy notice

`agt/approval.rego` and `agt/budgets.rego` are reduced local adaptations of
the corresponding files in the user-provided
`agent-control-standard-integration.zip`. Formatting, explanatory comments
and unused helpers were shortened; they are not byte-for-byte mirrors:

- upstream: `https://github.com/GenAI-Security-Project/agent-control-standard`;
- archive SHA-256: `BF87CB8EA31C7AB5CD2AF673C1AA41589E556BC715385C843FC0CE6AC35B6EAA`;
- source paths: `reference-implementations/agt/policy/lib/approval.rego` and
  `reference-implementations/agt/policy/lib/budgets.rego`;
- license: MIT, Copyright (c) Microsoft Corporation; see `agt/LICENSE-AGT`;
- upstream commit: not established from the supplied archive.

The repository has no OPA executable installed, so these Rego files are kept
for provenance and future native evaluation; they are not silently treated as
active. `l3/agt_controls.py` is an explicit, limited Python adaptation of the
tested budget/approval semantics and of the adjacent `egress.rego`/`ifc.rego`
algorithms. It additionally fails closed when a network destination is absent,
because the host classifies `network.send` as an egress action.
