import { NextResponse, type NextRequest } from "next/server";

const REALM = 'Basic realm="evm-auditor-panel", charset="UTF-8"';

function unauthorized() {
  return new NextResponse("Authentication required", {
    status: 401,
    headers: { "WWW-Authenticate": REALM },
  });
}

function decode(authHeader: string | null): { user: string; pass: string } | null {
  if (!authHeader || !authHeader.toLowerCase().startsWith("basic ")) return null;
  try {
    const raw = authHeader.slice(6);
    const decoded =
      typeof atob === "function"
        ? atob(raw)
        : Buffer.from(raw, "base64").toString("utf8");
    const idx = decoded.indexOf(":");
    if (idx < 0) return null;
    return { user: decoded.slice(0, idx), pass: decoded.slice(idx + 1) };
  } catch {
    return null;
  }
}

export function middleware(req: NextRequest) {
  const user = process.env.PANEL_USER;
  const pass = process.env.PANEL_PASS;
  if (!user || !pass) {
    return new NextResponse(
      "PANEL_USER and PANEL_PASS must be set in the environment.",
      { status: 503 },
    );
  }
  const got = decode(req.headers.get("authorization"));
  if (!got || got.user !== user || got.pass !== pass) {
    return unauthorized();
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\.svg).*)"],
};
