import { readFile } from "node:fs/promises";

export type BalanceConfig = { url: string; apiKeyFile: string };
export type BalanceSnapshot = {
  schema: "rewind.balance.v1";
  currency: "USD";
  availableUsd: string | null;
  exhausted: boolean;
  asOf: string;
};
export type BalanceReader = (config: BalanceConfig, signal?: AbortSignal) => Promise<BalanceSnapshot | undefined>;

export type BalanceReaderDependencies = {
  fetch?: typeof fetch;
  readFile?: (path: string, options: { encoding: "utf8"; signal?: AbortSignal }) => Promise<string>;
  timeoutMs?: number;
  maxBytes?: number;
};

const decimalPattern = /^\d{1,12}(?:\.\d{1,8})?$/;
const timestampPattern = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](\d{2}):(\d{2}))$/;

function validTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = timestampPattern.exec(value);
  if (!match || !Number.isFinite(Date.parse(value))) return false;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, offsetHourText, offsetMinuteText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1]
    && Number(hourText) <= 23 && Number(minuteText) <= 59 && Number(secondText) <= 59
    && (offsetHourText === undefined || (Number(offsetHourText) <= 23 && Number(offsetMinuteText) <= 59));
}

function isZero(value: string): boolean {
  return !/[1-9]/.test(value);
}

export function parseBalanceResponse(value: unknown): BalanceSnapshot | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (record.schema !== "rewind.balance.v1" || record.currency !== "USD"
    || typeof record.exhausted !== "boolean" || !validTimestamp(record.as_of)) return undefined;
  const available = record.available_usd;
  if (available !== null && (typeof available !== "string" || !decimalPattern.test(available))) return undefined;
  if (available === null ? record.exhausted : record.exhausted !== isZero(available)) return undefined;
  return {
    schema: "rewind.balance.v1",
    currency: "USD",
    availableUsd: available,
    exhausted: record.exhausted,
    asOf: record.as_of,
  };
}

async function boundedBody(response: Response, maxBytes: number): Promise<string | undefined> {
  const length = response.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxBytes)) {
    await response.body?.cancel().catch(() => {});
    return undefined;
  }
  if (!response.body) return undefined;
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytes = 0;
  let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) {
        await reader.cancel();
        return undefined;
      }
      text += decoder.decode(value, { stream: true });
    }
    return text + decoder.decode();
  } catch {
    return undefined;
  } finally {
    reader.releaseLock();
  }
}

export function createBalanceReader(dependencies: BalanceReaderDependencies = {}): BalanceReader {
  const fetchImpl = dependencies.fetch ?? fetch;
  const readKey = dependencies.readFile ?? readFile;
  const timeoutMs = dependencies.timeoutMs ?? 20_000;
  const maxBytes = dependencies.maxBytes ?? 16 * 1024;
  return async (config, signal) => {
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (signal?.aborted) controller.abort();
    else signal?.addEventListener("abort", abort, { once: true });
    const timeout = setTimeout(abort, timeoutMs);
    timeout.unref?.();
    try {
      const url = new URL(config.url);
      if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password || url.hash) return undefined;
      const apiKey = (await readKey(config.apiKeyFile, { encoding: "utf8", signal: controller.signal })).trim();
      if (!apiKey || apiKey.length > 8192 || /\s/.test(apiKey)) return undefined;
      const response = await fetchImpl(url, {
        method: "GET",
        headers: { accept: "application/json", authorization: `Bearer ${apiKey}` },
        redirect: "manual",
        signal: controller.signal,
      });
      if (!response.ok || response.status < 200 || response.status >= 300) {
        await response.body?.cancel().catch(() => {});
        return undefined;
      }
      const body = await boundedBody(response, maxBytes);
      if (body === undefined) return undefined;
      try {
        return parseBalanceResponse(JSON.parse(body));
      } catch {
        return undefined;
      }
    } catch {
      return undefined;
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
    }
  };
}

export const readBalance = createBalanceReader();

export function formatBalance(availableUsd: string | null): string | undefined {
  if (availableUsd === null || !decimalPattern.test(availableUsd)) return undefined;
  const [integer, fraction = ""] = availableUsd.split(".");
  if (isZero(availableUsd)) return "$0.00";
  if (BigInt(integer) === 0n && BigInt((fraction + "00000000").slice(0, 8)) < 1_000_000n) return "<$0.01";
  const padded = `${fraction}000`;
  let cents = BigInt(integer) * 100n + BigInt(padded.slice(0, 2));
  if (padded[2] >= "5") cents++;
  const dollars = cents / 100n;
  return `$${dollars}.${String(cents % 100n).padStart(2, "0")}`;
}
