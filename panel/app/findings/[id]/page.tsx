import { FindingDetail } from "@/src/components/FindingDetail";

export default async function FindingDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <FindingDetail id={id} />;
}
