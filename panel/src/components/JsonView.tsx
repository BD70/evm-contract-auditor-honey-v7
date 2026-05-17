"use client";

import { Box, Button, HStack, Text } from "@chakra-ui/react";
import { useState } from "react";
import { LuCopy } from "react-icons/lu";

export function JsonView({ value, maxHeight = "60vh" }: { value: unknown; maxHeight?: string }) {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  const [copied, setCopied] = useState(false);
  return (
    <Box position="relative">
      <HStack position="absolute" top="2" right="2" zIndex="1">
        <Button
          size="xs"
          variant="subtle"
          onClick={async () => {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          }}
        >
          <LuCopy />
          <Text ml="1">{copied ? "copied" : "copy"}</Text>
        </Button>
      </HStack>
      <Box
        as="pre"
        bg="bg.inverted"
        color="fg.inverted"
        rounded="md"
        p="3"
        fontFamily="mono"
        fontSize="xs"
        overflow="auto"
        maxH={maxHeight}
        whiteSpace="pre"
      >
        {text}
      </Box>
    </Box>
  );
}
