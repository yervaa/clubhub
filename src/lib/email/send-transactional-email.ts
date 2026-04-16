import "server-only";

export type TransactionalEmailPayload = {
  to: string;
  subject: string;
  text: string;
};

/**
 * Sends email via Resend HTTP API when `RESEND_API_KEY` is set.
 * If not configured, logs once per process and returns ok:false (in-app still works).
 */
export async function sendTransactionalEmail(payload: TransactionalEmailPayload): Promise<{ ok: boolean; skipped?: boolean }> {
  const apiKey = process.env.RESEND_API_KEY?.trim();
  const from = process.env.RESEND_FROM_EMAIL?.trim() || "ClubHub <onboarding@resend.dev>";

  if (!apiKey) {
    console.info("[email] RESEND_API_KEY not set; skipping email send:", payload.subject);
    return { ok: false, skipped: true };
  }

  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from,
        to: [payload.to],
        subject: payload.subject,
        text: payload.text,
      }),
    });

    if (!res.ok) {
      const errText = await res.text();
      console.error("[email] Resend error:", res.status, errText);
      return { ok: false };
    }

    return { ok: true };
  } catch (e) {
    console.error("[email] Resend fetch failed:", e);
    return { ok: false };
  }
}
