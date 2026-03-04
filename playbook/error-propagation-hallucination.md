# Error Propagation Hallucination

**Pattern:** Unstructured error text fed into an LLM context causes the agent to hallucinate a confident but fabricated recovery action.

**Severity trend:** Functional

**Incidents:** 2026-03-04-002

## Description

When a tool invocation or system call fails, the error is caught and converted to a plain text string (e.g., `"ERROR: Tool X failed with: <exception>"`) that gets fed back into the agent's context window. The LLM treats this as informational content to reason about rather than a structured error signal. It generates a plausible-sounding but fabricated solution, often presented with high confidence.

This is a compound failure: the unstructured error propagation triggers a hallucination, which is then amplified by confidence miscalibration. The user sees a convincing recovery action that was invented from raw exception text.

## Detection

- Exception handlers that convert errors to format strings fed back to the LLM
- `f"ERROR: {tool_name} failed with: {exc}"` or similar patterns in agent context
- Agent responses after tool failures that contain specific technical actions not present in the error output
- Grep pattern: `except.*:.*f".*ERROR.*{.*}.*failed`

## Prevention

1. **Use structured error metadata.** Return typed error objects (error code, retryable boolean, suggested user action) instead of raw exception strings.
2. **Add system prompt guardrails.** Instruct the agent that on tool failure, it must acknowledge the failure explicitly and offer to retry — never attempt to reason through raw error output.
3. **Separate error signals from content.** Errors should flow through a distinct channel (tool result status codes, dedicated error fields) not as text appended to conversation context.
4. **Validate recovery actions.** If the agent proposes a fix after a failure, require it to cite the source of the fix (documentation, prior successful call) rather than generating one from the error text alone.

## Response Protocol

When this pattern is detected:

1. Identify all exception handlers that feed error text back into agent context
2. Replace raw error strings with structured error metadata
3. Add system prompt instructions for explicit failure acknowledgment
4. Test with intentional tool failures to verify the agent doesn't hallucinate recovery actions
5. Consider adding a confidence-reduction signal when tool failures occur
