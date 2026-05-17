"use client";

import { Box, Button, Code, Heading, Stack, Text } from "@chakra-ui/react";
import { useEffect } from "react";

// Next.js per-route error boundary. Catches client-side render/effect
// errors thrown inside the route subtree (anything under app/) and
// renders this fallback instead of crashing the whole tab. The "reset"
// button lets the user retry the failed render without a hard reload.
//
// We deliberately keep this minimal and link-free — anything fancier
// (e.g. a back button, a "report this" form) just adds more surface
// that could itself throw.
export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("[panel/error.tsx]", error);
  }, [error]);

  return (
    <Box
      m="6"
      p="6"
      rounded="lg"
      border="1px solid"
      borderColor="red.muted"
      bg="red.subtle"
      color="red.fg"
      maxW="900px"
    >
      <Stack gap="3">
        <Heading size="md">Something broke in this view</Heading>
        <Text fontSize="sm">
          The rest of the panel is still healthy — only this page failed to
          render. You can retry, navigate elsewhere, or copy the message
          below if you want to file it.
        </Text>
        <Code
          fontSize="xs"
          fontFamily="mono"
          p="3"
          rounded="md"
          whiteSpace="pre-wrap"
          maxH="200px"
          overflowY="auto"
        >
          {error?.message ?? String(error)}
          {error?.digest ? `\n\ndigest: ${error.digest}` : ""}
        </Code>
        <Box>
          <Button size="sm" colorPalette="red" onClick={() => reset()}>
            Retry this view
          </Button>
        </Box>
      </Stack>
    </Box>
  );
}
