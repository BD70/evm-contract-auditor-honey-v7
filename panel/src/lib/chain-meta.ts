// Static mapping between runner chain slugs (from chains.json) and on-chain
// chainIds + native-token metadata. The runner stores findings with chainId
// (e.g. 1, 137) but the per-chain RPC URLs in chains.json are keyed by slug.
// We use this table to bridge the two and to render native amounts correctly.

export interface ChainMeta {
  slug: string;
  chainId: number;
  nativeSymbol: string;
  nativeDecimals: number;
}

export const CHAIN_META: ChainMeta[] = [
  { slug: "eth-mainnet", chainId: 1, nativeSymbol: "ETH", nativeDecimals: 18 },
  { slug: "bsc-mainnet", chainId: 56, nativeSymbol: "BNB", nativeDecimals: 18 },
  { slug: "polygon-mainnet", chainId: 137, nativeSymbol: "MATIC", nativeDecimals: 18 },
  { slug: "optimism-mainnet", chainId: 10, nativeSymbol: "ETH", nativeDecimals: 18 },
  { slug: "base-mainnet", chainId: 8453, nativeSymbol: "ETH", nativeDecimals: 18 },
  { slug: "arbitrum-mainnet", chainId: 42161, nativeSymbol: "ETH", nativeDecimals: 18 },
  { slug: "avalanche-mainnet", chainId: 43114, nativeSymbol: "AVAX", nativeDecimals: 18 },
  { slug: "blast-mainnet", chainId: 81457, nativeSymbol: "ETH", nativeDecimals: 18 },
  { slug: "celo-mainnet", chainId: 42220, nativeSymbol: "CELO", nativeDecimals: 18 },
  { slug: "zksync-mainnet", chainId: 324, nativeSymbol: "ETH", nativeDecimals: 18 },
  { slug: "xai-mainnet", chainId: 660279, nativeSymbol: "XAI", nativeDecimals: 18 },
  { slug: "sonic-mainnet", chainId: 146, nativeSymbol: "S", nativeDecimals: 18 },
  { slug: "linea-mainnet", chainId: 59144, nativeSymbol: "ETH", nativeDecimals: 18 },
  { slug: "gnosis-mainnet", chainId: 100, nativeSymbol: "xDAI", nativeDecimals: 18 },
];

const BY_CHAIN_ID = new Map(CHAIN_META.map((m) => [m.chainId, m] as const));
const BY_SLUG = new Map(CHAIN_META.map((m) => [m.slug, m] as const));

export function chainMetaByChainId(chainId: number | null | undefined): ChainMeta | null {
  if (chainId == null) return null;
  return BY_CHAIN_ID.get(chainId) ?? null;
}

export function chainMetaBySlug(slug: string | null | undefined): ChainMeta | null {
  if (!slug) return null;
  return BY_SLUG.get(slug) ?? null;
}
