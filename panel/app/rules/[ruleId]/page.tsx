import { RuleDetail } from "@/src/components/RuleDetail";

export default async function RulePage({ params }: { params: Promise<{ ruleId: string }> }) {
  const { ruleId } = await params;
  return <RuleDetail ruleId={decodeURIComponent(ruleId)} />;
}
