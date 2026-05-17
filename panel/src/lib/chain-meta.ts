// Static mapping between runner chain slugs (from chains.json) and on-chain
// chainIds + native-token metadata. The runner stores findings with chainId
// (e.g. 1, 137) but the per-chain RPC URLs in chains.json are keyed by slug.
// We use this table to bridge the two and to render native amounts correctly.

export interface ChainMeta {
  slug: string;
  chainId: number;
  nativeSymbol: string;
  nativeDecimals: number;
  /** Block-explorer base URL (no trailing slash). When set we expose a one-
   *  click "open on explorer" link from the findings table. We deliberately
   *  prefer the *.scan brand for each chain because that's what auditors
   *  reflexively look for ("etherscan", "bscscan"); falls back to the chain's
   *  canonical explorer where no *.scan exists. */
  explorerUrl?: string;
}

export const CHAIN_META: ChainMeta[] = [
  { slug: "eth-mainnet", chainId: 1, nativeSymbol: "ETH", nativeDecimals: 18, explorerUrl: "https://etherscan.io" },
  { slug: "bsc-mainnet", chainId: 56, nativeSymbol: "BNB", nativeDecimals: 18, explorerUrl: "https://bscscan.com" },
  { slug: "polygon-mainnet", chainId: 137, nativeSymbol: "MATIC", nativeDecimals: 18, explorerUrl: "https://polygonscan.com" },
  { slug: "optimism-mainnet", chainId: 10, nativeSymbol: "ETH", nativeDecimals: 18, explorerUrl: "https://optimistic.etherscan.io" },
  { slug: "base-mainnet", chainId: 8453, nativeSymbol: "ETH", nativeDecimals: 18, explorerUrl: "https://basescan.org" },
  { slug: "arbitrum-mainnet", chainId: 42161, nativeSymbol: "ETH", nativeDecimals: 18, explorerUrl: "https://arbiscan.io" },
  { slug: "avalanche-mainnet", chainId: 43114, nativeSymbol: "AVAX", nativeDecimals: 18, explorerUrl: "https://snowtrace.io" },
  { slug: "blast-mainnet", chainId: 81457, nativeSymbol: "ETH", nativeDecimals: 18, explorerUrl: "https://blastscan.io" },
  { slug: "celo-mainnet", chainId: 42220, nativeSymbol: "CELO", nativeDecimals: 18, explorerUrl: "https://celoscan.io" },
  { slug: "zksync-mainnet", chainId: 324, nativeSymbol: "ETH", nativeDecimals: 18, explorerUrl: "https://explorer.zksync.io" },
  { slug: "xai-mainnet", chainId: 660279, nativeSymbol: "XAI", nativeDecimals: 18, explorerUrl: "https://explorer.xai-chain.net" },
  { slug: "sonic-mainnet", chainId: 146, nativeSymbol: "S", nativeDecimals: 18, explorerUrl: "https://sonicscan.org" },
  { slug: "linea-mainnet", chainId: 59144, nativeSymbol: "ETH", nativeDecimals: 18, explorerUrl: "https://lineascan.build" },
  { slug: "gnosis-mainnet", chainId: 100, nativeSymbol: "xDAI", nativeDecimals: 18, explorerUrl: "https://gnosisscan.io" },
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

/** Build a deep-link to a contract address on the chain's canonical block
 *  explorer. Returns null when the chain isn't in our table or has no
 *  explorer configured (so callers can hide the button gracefully). */
export function explorerAddressUrl(
  chainId: number | null | undefined,
  address: string | null | undefined,
): string | null {
  if (!address || !/^0x[0-9a-fA-F]{40}$/.test(address)) return null;
  const meta = chainMetaByChainId(chainId ?? null);
  if (!meta?.explorerUrl) return null;
  return `${meta.explorerUrl}/address/${address}`;
}
