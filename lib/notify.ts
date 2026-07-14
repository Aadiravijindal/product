/**
 * Outbound notifications. Set SLACK_WEBHOOK_URL (a Slack incoming-webhook or
 * any endpoint accepting {"text": "..."}) and the platform pushes the events
 * a security team actually wants interrupted for: drift on watched repos,
 * completed fix runs, opened PRs, policy blocks. No-op when unset.
 */
export async function notify(text: string): Promise<void> {
  const url = process.env.SLACK_WEBHOOK_URL;
  if (!url) return;
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text }),
    });
  } catch {
    // notifications are best-effort; never break the pipeline over them
  }
}
