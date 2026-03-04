# Silent Fallback

**Pattern:** System catches an error and falls back to a degraded mode without notifying the operator.

**Severity trend:** Functional to safety-critical

**Incidents:** 2026-03-04-001, 2026-03-04-004

## Description

When a system component fails (database connection, matrix computation, external service), the code catches the exception, logs a warning, and continues with a reduced-capability fallback. The operator has no indication that the system is degraded.

This pattern is especially dangerous in safety-critical contexts (ISR, medical, infrastructure monitoring) where the operator's decision-making depends on system integrity they can no longer verify.

## Detection

- `try/except` blocks that log at WARNING level and substitute a fallback
- Fallback code paths with no user-facing notification
- Error handling that converts failures to "continue silently" behavior
- Grep pattern: `except.*:.*log.*(warn|warning)` followed by fallback assignment

## Prevention

1. **Distinguish graceful from silent.** Graceful degradation means "continues working AND tells someone." Silent degradation means "continues working AND hides the problem."
2. **Surface degradation to operators.** Any fallback path must produce an operator-visible signal — system message, status indicator, health check flag.
3. **Classify by blast radius.** A cosmetic fallback (e.g., default avatar) can be silent. A data-integrity fallback (e.g., in-memory instead of persistent store) must not be.
4. **Add startup health checks.** Verify critical components are active at startup, not just at first use.

## Response Protocol

When this pattern is detected in code review or incident investigation:

1. Identify all fallback paths in the affected component
2. Classify each as cosmetic, functional, or safety-critical
3. For functional and safety-critical: add operator notification
4. Add monitoring/alerting for fallback activation
5. Document the degraded state in the system's health endpoint
