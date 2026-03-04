# Forge Playbook — Table of Contents

This is the living playbook of AI agent failure modes documented through USMI's Forge system. Each entry describes a recurring pattern, its detection methods, prevention strategies, and response protocols.

## Entries

- [Silent Fallback](silent-fallback.md) — System degrades without notifying the operator (incidents 001, 004)

## How entries are created

1. Incidents are logged via `forge log`
2. Periodic analysis via `forge analyze` identifies patterns
3. Patterns with 3+ occurrences or safety-critical severity get playbook entries
4. Entries are updated as new incidents refine understanding
