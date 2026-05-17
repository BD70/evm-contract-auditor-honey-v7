
import { EventEmitter } from "node:events";

type GlobalBus = { __panelEventBus?: EventEmitter };
const g = globalThis as unknown as GlobalBus;
if (!g.__panelEventBus) {
  const bus = new EventEmitter();
  bus.setMaxListeners(1000);
  g.__panelEventBus = bus;
}

export const eventBus = g.__panelEventBus!;

export type FindingEvent = {
  id: string;
  ruleId: string;
  severity: string;
  title: string | null;
  source: "runner" | "manual";
  discoveredAt: number;
};
