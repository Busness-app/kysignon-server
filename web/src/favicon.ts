export function faviconUrl(siteUrl: string): string | undefined {
  try {
    return new URL('/favicon.ico', siteUrl).toString();
  } catch {
    return undefined;
  }
}
