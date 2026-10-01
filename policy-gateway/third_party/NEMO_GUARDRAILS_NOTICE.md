# NeMo Guardrails code provenance

The file `policy-gateway/l1/nemo_jailbreak.py` is adapted from:

- archive: `Guardrails-develop.zip` supplied by the project user;
- upstream path: `nemoguardrails/library/jailbreak_detection/request.py`;
- upstream copyright: Copyright (c) 2023-2026 NVIDIA CORPORATION & AFFILIATES;
- license: Apache License 2.0 (`Guardrails-develop/LICENSE.md`).

The adaptation preserves the upstream JSON request/response contract but uses
the Python standard library, restricts the endpoint to loopback addresses, and
supports an injected transport for tests. It does not include or download the
upstream GPT-2 Large, Torch, Transformers, NIM service, or NeMo runtime.

The unmodified [Apache License 2.0 text](licenses/NEMO-Apache-2.0.txt)
and [upstream license notice](licenses/NEMO-LICENSE.md) are included.
Their bytes were compared with the supplied archive, not reconstructed.
