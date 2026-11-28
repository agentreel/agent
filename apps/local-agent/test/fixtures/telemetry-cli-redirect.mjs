const origin = process.env.AGENTREEL_TEST_TELEMETRY_ORIGIN;
const baseFetch = globalThis.fetch;

globalThis.fetch = (url, init) => {
  const target = String(url);
  if (origin && target.includes("agentreel.dev/api/cli/events")) {
    const redirectUrl = new URL(new URL(target).pathname, origin).href;
    return baseFetch(redirectUrl, init);
  }
  return baseFetch(url, init);
};
