import type { RunnerConfig, WebhookEvent } from "./types.js";
import { isTransientHttpStatus, isTransientNetworkError, lowerCaseHeaderMap, retry } from "./utils.js";

export async function postWebhook(config: RunnerConfig, event: WebhookEvent, dryRun: boolean): Promise<void> {
  if (!config.webhookUrl || dryRun) {
    return;
  }
  await retry(
    async () => {
      const headers: Record<string, string> = {
        "content-type": "application/json",
        ...lowerCaseHeaderMap(config.webhookAuthHeader),
      };
      const response = await fetch(config.webhookUrl!, {
        method: "POST",
        headers,
        body: JSON.stringify(event),
      });
      if (!response.ok) {
        throw new Error(`webhook http ${response.status}`);
      }
    },
    {
      attempts: config.webhookMaxAttempts,
      baseDelayMs: config.retryBaseDelayMs,
      shouldRetry: (error) => isWebhookRetryable(error),
    },
  );
}

export function isWebhookRetryable(error: unknown): boolean {
  if (isTransientNetworkError(error)) {
    return true;
  }
  if (!(error instanceof Error)) {
    return false;
  }
  const match = error.message.match(/http (\d+)/);
  return match ? isTransientHttpStatus(Number.parseInt(match[1] ?? "", 10)) : false;
}
