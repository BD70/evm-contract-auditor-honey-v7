import { Heading, Stack } from "@chakra-ui/react";
import { LogStream } from "@/src/components/LogStream";

export default function LogsPage() {
  return (
    <Stack gap="4">
      <Heading size="lg">Runner Logs</Heading>
      <LogStream />
    </Stack>
  );
}
