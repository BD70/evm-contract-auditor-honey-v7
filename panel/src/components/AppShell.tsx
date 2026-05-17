"use client";

import {
  Box,
  Flex,
  HStack,
  Heading,
  Stack,
  Text,
  IconButton,
} from "@chakra-ui/react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LuGauge,
  LuBug,
  LuTerminal,
  LuPlay,
  LuSettings,
  LuScrollText,
  LuNetwork,
} from "react-icons/lu";
import { ColorModeButton } from "./ui/color-mode";
import { RunnerPill } from "./RunnerPill";

const NAV = [
  { href: "/", label: "Dashboard", icon: LuGauge },
  { href: "/findings", label: "Findings", icon: LuBug },
  { href: "/test", label: "Test", icon: LuPlay },
  { href: "/rules", label: "Rules", icon: LuScrollText },
  { href: "/chains", label: "Chains", icon: LuNetwork },
  { href: "/config", label: "Config", icon: LuSettings },
  { href: "/logs", label: "Logs", icon: LuTerminal },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  return (
    <Flex minH="100vh" bg="bg.subtle">
      <Stack
        as="nav"
        w={{ base: "60px", md: "220px" }}
        bg="bg.panel"
        borderRight="1px solid"
        borderColor="border"
        p="3"
        gap="1"
        position="sticky"
        top="0"
        h="100vh"
      >
        <HStack mb="3" px="1" gap="2">
          <Box w="8" h="8" rounded="md" bg="purple.500" color="white" display="grid" placeItems="center" fontWeight="bold">
            E
          </Box>
          <Heading size="sm" display={{ base: "none", md: "block" }}>
            EVM Auditor
          </Heading>
        </HStack>
        {NAV.map((item) => {
          const active = item.href === "/" ? pathname === "/" : pathname?.startsWith(item.href);
          const Icon = item.icon;
          return (
            <Link key={item.href} href={item.href} style={{ textDecoration: "none" }}>
              <HStack
                px="2.5"
                py="2"
                rounded="md"
                bg={active ? "bg.emphasized" : "transparent"}
                _hover={{ bg: "bg.muted" }}
                color={active ? "fg" : "fg.muted"}
                gap="3"
              >
                <Icon size={16} />
                <Text fontSize="sm" display={{ base: "none", md: "block" }}>
                  {item.label}
                </Text>
              </HStack>
            </Link>
          );
        })}
      </Stack>
      <Flex direction="column" flex="1" minW="0">
        <HStack
          h="56px"
          px="5"
          borderBottom="1px solid"
          borderColor="border"
          bg="bg.panel"
          justify="space-between"
          position="sticky"
          top="0"
          zIndex="1"
        >
          <RunnerPill />
          <HStack gap="2">
            <ColorModeButton />
          </HStack>
        </HStack>
        <Box as="main" p="5" flex="1" minW="0">
          {children}
        </Box>
      </Flex>
    </Flex>
  );
}
