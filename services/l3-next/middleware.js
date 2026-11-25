import { NextResponse } from "next/server";

export function middleware(request) {
  
  
  
  const loginUrl = new URL("/login", request.url);
  return NextResponse.redirect(loginUrl);
}

export const config = {
  matcher: ["/((?!api|static|.*\\..*|_next|favicon.ico|robots.txt|login).*)"],
};
