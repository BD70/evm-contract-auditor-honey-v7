// Lightweight Telegram bot for the rescue pipeline.
//
// Why no `node-telegram-bot-api`: TG's HTTP Bot API is straightforward and
// the panel only needs a handful of methods (sendMessage, getUpdates). Each
// new dependency is a supply-chain liability on a tool that ends up holding
// rescue-grade private keys, so we keep this implementation deliberately
// thin.
//
// Lifecycle:
//   1. On boot (see boot.ts), startTgBot() spins up a long-poll loop if
//      TG_BOT_TOKEN is set. Without it, the bot is a no-op (panel still
//      works, just no chat notifications).
//   2. notifyPoe(poe) — called by rescue-prove.ts (via the existing
//      RESCUE_NOTIFY_URL webhook) AND optionally directly here. Posts a
//      summary to TG_CHAT_ID with inline-button command hints.
//   3. The long-poll loop handles /commands:
//        /start         — sanity check
//        /poe <id>      — fetch and render the PoE summary
//        /timeline <id> — show the rescue-action log
//        /rescue <id> [auth] — broadcast the drain plan (dry-run by
//                              default; live only if RESCUE_BROADCAST_ENABLED
//                              and the operator includes the auth token)
//
// Authorisation: incoming TG updates are filtered by TG_ALLOWED_CHAT_IDS
// (comma-separated) so random chats can't trigger rescue actions.

import { loadActionsForFinding, loadLatestPoe, logRescueAction } from "../sim/poe-store";
import { broadcastRescue } from "./broadcaster";

const TG_API_BASE = "https://api.telegram.org/bot";
const TG_BOT_TOKEN = process.env.TG_BOT_TOKEN ?? "";
const TG_CHAT_ID = process.env.TG_CHAT_ID ?? ""; // primary notify destination
const TG_ALLOWED_CHAT_IDS = (process.env.TG_ALLOWED_CHAT_IDS ?? TG_CHAT_ID)
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const TG_POLL_TIMEOUT_S = Number(process.env.TG_POLL_TIMEOUT_S ?? 30);

let started = false;
let stopFlag = false;

export function tgBotEnabled(): boolean {
  return !!TG_BOT_TOKEN;
}

export async function startTgBot(): Promise<void> {
  if (started || !tgBotEnabled()) return;
  started = true;
  console.log("[tg-bot] starting long-poll loop");
  void pollLoop().catch((e) => console.warn("[tg-bot] loop crashed", e));
}

export function stopTgBot(): void {
  stopFlag = true;
}

// ---- outbound -------------------------------------------------------------

export async function notifyPoe(args: {
  findingId: string;
  chainId: number;
  contractAddress: string;
  verdict: string;
  totalRescuedUsd: number | null;
  rescuedCount: number;
  escrow: string;
  blockNumber: number | null;
}): Promise<boolean> {
  if (!tgBotEnabled() || !TG_CHAT_ID) return false;
  const usd =
    args.totalRescuedUsd == null
      ? "—"
      : `$${args.totalRescuedUsd.toLocaleString("en-US", { maximumFractionDigits: 2 })}`;
  const lines = [
    `*RESCUE-PROVE*  \`${args.verdict}\``,
    `chain: \`${args.chainId}\`   block: \`${args.blockNumber ?? "?"}\``,
    `contract: \`${args.contractAddress}\``,
    `rescuable assets: *${args.rescuedCount}*  ·  total at risk: *${usd}*`,
    `escrow: \`${args.escrow}\``,
    ``,
    `Commands:`,
    `  /poe \`${args.findingId}\``,
    `  /timeline \`${args.findingId}\``,
    `  /rescue \`${args.findingId}\`  (dry-run by default)`,
  ];
  return await tgSendMessage(TG_CHAT_ID, lines.join("\n"));
}

async function tgSendMessage(chatId: string, text: string): Promise<boolean> {
  if (!tgBotEnabled()) return false;
  try {
    const r = await fetch(`${TG_API_BASE}${TG_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: "Markdown", disable_web_page_preview: true }),
    });
    return r.ok;
  } catch (e) {
    console.warn("[tg-bot] sendMessage failed", e);
    return false;
  }
}

// ---- long-poll loop -------------------------------------------------------

async function pollLoop(): Promise<void> {
  let offset = 0;
  while (!stopFlag) {
    try {
      const r = await fetch(
        `${TG_API_BASE}${TG_BOT_TOKEN}/getUpdates?timeout=${TG_POLL_TIMEOUT_S}&offset=${offset}`,
      );
      if (!r.ok) {
        await new Promise((res) => setTimeout(res, 5000));
        continue;
      }
      const j = (await r.json()) as any;
      const updates: any[] = Array.isArray(j?.result) ? j.result : [];
      for (const u of updates) {
        offset = Math.max(offset, (u.update_id ?? 0) + 1);
        await handleUpdate(u).catch((e) => console.warn("[tg-bot] handleUpdate", e));
      }
    } catch (e) {
      console.warn("[tg-bot] poll error", e);
      await new Promise((res) => setTimeout(res, 5000));
    }
  }
}

async function handleUpdate(u: any): Promise<void> {
  const msg = u?.message ?? u?.channel_post;
  if (!msg) return;
  const chatId = String(msg.chat?.id ?? "");
  if (TG_ALLOWED_CHAT_IDS.length > 0 && !TG_ALLOWED_CHAT_IDS.includes(chatId)) {
    return;
  }
  const text: string = String(msg.text ?? "").trim();
  if (!text.startsWith("/")) return;
  const parts = text.split(/\s+/);
  const cmd = parts[0].toLowerCase().split("@")[0];
  const sender = msg.from?.username ?? `id:${msg.from?.id ?? "?"}`;

  try {
    if (cmd === "/start") {
      await tgSendMessage(
        chatId,
        "rescue-bot ready. Try `/poe <findingId>` once a PoE has been generated.",
      );
    } else if (cmd === "/poe") {
      const id = parts[1];
      if (!id) return void tgSendMessage(chatId, "usage: `/poe <findingId>`");
      const poe = loadLatestPoe(id);
      if (!poe) return void tgSendMessage(chatId, `no PoE for finding \`${id}\``);
      const usd =
        poe.totalRescuedUsd == null
          ? "—"
          : `$${poe.totalRescuedUsd.toLocaleString("en-US", { maximumFractionDigits: 2 })}`;
      const assetLines = poe.rescuedAssets
        .map(
          (a) =>
            `  • ${a.symbol} — ${a.amountBase} (${a.token ?? "native"})${
              a.usdValue != null ? `  ≈ $${a.usdValue.toFixed(2)}` : ""
            }`,
        )
        .join("\n");
      await tgSendMessage(
        chatId,
        [
          `*PoE*  \`${poe.findingId}\`  → \`${poe.verdict}\``,
          `chain ${poe.chainId}  block ${poe.blockNumber ?? "?"}`,
          `contract: \`${poe.contractAddress}\``,
          `escrow:   \`${poe.escrowAddress}\``,
          `attacker: ${poe.attackerKind}`,
          `assets (${poe.rescuedAssets.length}):`,
          assetLines || "  —",
          ``,
          `total at risk: *${usd}*`,
          `drain plan: ${poe.drainPlan.length} step(s),  ${poe.drainPlan.filter((s) => s.success).length} succeeded on fork`,
        ].join("\n"),
      );
    } else if (cmd === "/timeline") {
      const id = parts[1];
      if (!id) return void tgSendMessage(chatId, "usage: `/timeline <findingId>`");
      const rows = loadActionsForFinding(id);
      if (rows.length === 0) return void tgSendMessage(chatId, `no actions for \`${id}\``);
      const lines = rows.slice(-25).map((r) => {
        const ts = new Date(r.at).toISOString().replace("T", " ").slice(0, 19);
        return `${ts}  ${r.kind}${r.actor ? `  (${r.actor})` : ""}`;
      });
      await tgSendMessage(chatId, `*Timeline* \`${id}\`\n\`\`\`\n${lines.join("\n")}\n\`\`\``);
    } else if (cmd === "/rescue") {
      const id = parts[1];
      const auth = parts[2] ?? null;
      if (!id) return void tgSendMessage(chatId, "usage: `/rescue <findingId> [auth_token]`");
      const poe = loadLatestPoe(id);
      if (!poe) return void tgSendMessage(chatId, `no PoE for finding \`${id}\``);
      const mode = auth ? "live" : "dry-run-fork";
      logRescueAction({
        findingId: id,
        attemptId: poe.attemptId,
        kind: "rescue-requested",
        actor: `tg:${sender}`,
        detail: { mode, viaCommand: cmd },
      });
      const result = await broadcastRescue({ poe, mode, authToken: auth });
      const succeeded = result.results.filter((r) => !r.error).length;
      const failed = result.results.filter((r) => r.error).length;
      const txList = result.results
        .filter((r) => r.txHash)
        .map((r) => `  • ${r.asset}  →  ${r.txHash}`)
        .join("\n");
      await tgSendMessage(
        chatId,
        [
          `*Rescue ${mode}*  \`${id}\`  →  ok=${result.ok}`,
          result.error ? `error: \`${result.error}\`` : "",
          `steps: ${result.results.length}  ok=${succeeded}  failed=${failed}`,
          txList,
        ]
          .filter(Boolean)
          .join("\n"),
      );
    } else if (cmd === "/help") {
      await tgSendMessage(
        chatId,
        "/start · /poe <id> · /timeline <id> · /rescue <id> [auth_token]",
      );
    }
  } catch (e: any) {
    await tgSendMessage(chatId, `error: \`${String(e?.message ?? e).slice(0, 240)}\``);
  }
}
