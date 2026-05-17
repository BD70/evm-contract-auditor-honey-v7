export const CHAINS: { id: number; name: string; defaultRpc?: string }[] = [
  { id: 1, name: "Ethereum Mainnet" },
  { id: 11155111, name: "Sepolia" },
  { id: 8453, name: "Base" },
  { id: 84532, name: "Base Sepolia" },
  { id: 42161, name: "Arbitrum One" },
  { id: 421614, name: "Arbitrum Sepolia" },
  { id: 10, name: "Optimism" },
  { id: 11155420, name: "Optimism Sepolia" },
  { id: 137, name: "Polygon" },
  { id: 80002, name: "Polygon Amoy" },
  { id: 56, name: "BSC" },
  { id: 43114, name: "Avalanche" },
  { id: 100, name: "Gnosis" },
];

export function chainName(id: number | null | undefined): string {
  if (id == null) return "—";
  return CHAINS.find((c) => c.id === id)?.name ?? `chain ${id}`;
}
