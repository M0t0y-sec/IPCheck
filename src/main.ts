/** Card controller.
 *
 * The Rust side owns all judgement (scores, bands, what changed). This file
 * only renders, plus two bits of local state the backend has no business
 * knowing about: whether the card is expanded, and whether a refresh is in
 * flight.
 */

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow, LogicalSize } from "@tauri-apps/api/window";
import type { Band, Snapshot, Update } from "./types";

// ---------------------------------------------------------------- helpers

const $ = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el as T;
};

/** Risk band, mirroring score::risk_band in Rust so the two cannot disagree. */
function riskBand(risk: number): Band {
  if (risk <= 19) return "green";
  if (risk <= 39) return "blue";
  if (risk <= 59) return "yellow";
  if (risk <= 79) return "orange";
  return "red";
}

/** Composite-quality band, mirroring score::quality_band. */
function qualityBand(composite: number): Band {
  if (composite >= 80) return "green";
  if (composite >= 60) return "blue";
  if (composite >= 40) return "yellow";
  if (composite >= 20) return "orange";
  return "red";
}

/** Localised label for the IP type the backend classified. */
function typeLabel(t: string): string {
  switch (t) {
    case "residential": return "住宅";
    case "mobile": return "移动";
    case "business": return "企业";
    case "hosting": return "机房";
    default: return "未知";
  }
}

function relativeTime(ms: number): string {
  const secs = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (secs < 60) return `${secs}s 前刷新`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}min 前刷新`;
  return `${Math.round(mins / 60)}h 前刷新`;
}

/** Country badge text.
 *
 * Deliberately the two-letter code, not a flag emoji: Windows' Segoe UI Emoji
 * has no regional-indicator glyphs, so a flag renders as the letters anyway —
 * just less legibly and with inconsistent metrics. Using the code directly
 * makes the fallback the design. Falls back to a dot pair when the code is
 * missing or malformed. */
function countryBadge(cc: string): string {
  if (!/^[A-Za-z]{2}$/.test(cc)) return "··";
  return cc.toUpperCase();
}

// -------------------------------------------------------------------- state

let expanded = false;
let refreshing = false;
let lastSnapshot: Snapshot | null = null;
/** Set when a press turned into a drag, so the trailing `click` is ignored.
 *  Without this, dragging the card would also toggle it open. */
let suppressNextClick = false;
/** Last expanded height we applied, so `fitWindow` can skip no-op resizes and
 *  avoid a resize -> reflow -> resize feedback loop. */
let lastFitH = -1;

// ------------------------------------------------------------------ render

function renderCollapsed(s: Snapshot): void {
  $("c-flag").textContent = countryBadge(s.countryCode);
  $("c-ip").textContent = s.ip || "—";
  $("c-type").textContent = typeLabel(s.ipType);

  const band = qualityBand(s.composite);
  const dot = $("c-dot");
  dot.dataset.band = band;
  $("c-score").textContent = String(s.composite);
}

function renderExpanded(s: Snapshot): void {
  $("e-flag").textContent = countryBadge(s.countryCode);
  $("e-ip").textContent = s.ip || "—";

  // Scores. Risk is displayed as-is (high = bad) but its bar is colour-coded
  // by the risk band so the visual reading matches the number.
  const cells: Array<[string, number, Band]> = [
    ["purity", s.scores.purity, qualityBand(s.scores.purity)],
    ["risk", s.scores.risk, riskBand(s.scores.risk)],
    ["confidence", s.scores.confidence, qualityBand(s.scores.confidence)],
    ["consistency", s.scores.consistency, qualityBand(s.scores.consistency)],
  ];

  for (const [key, value, band] of cells) {
    const num = $(`s-${key}`);
    num.textContent = String(value);
    // Colour the number by its own band, so a low confidence cannot render in
    // the same green as a high one.
    num.dataset.band = band;
    const bar = $(`b-${key}`) as HTMLElement;
    bar.style.width = `${value}%`;
    bar.dataset.band = band;
  }

  // Facts.
  $("f-asn").textContent = [s.asn, s.org].filter(Boolean).join(" ") || "—";
  $("f-isp").textContent = s.isp || "—";

  const loc = [s.country, s.region, s.city].filter(Boolean).join(" / ") || "—";
  $("f-loc").textContent = loc;
  $("f-tz").textContent = s.timezone || "—";

  const domesticIp = $("f-domestic-ip");
  domesticIp.textContent = s.domesticIp || "未探测";
  $("f-domestic-meta").textContent = s.domesticResponded
    ? `${s.domesticAgree}/${s.domesticResponded} 个端点一致`
    : "国内路径不可达";
  const internationalIp = $("f-international-ip");
  internationalIp.textContent = s.internationalIp || "未探测";
  $("f-international-meta").textContent = s.internationalResponded
    ? `${s.internationalAgree}/${s.internationalResponded} 个端点一致 · HTTPS`
    : "外网路径不可达或被拦截";

  const bl = $("f-bl");
  if (s.blacklistChecked === 0) {
    bl.textContent = "未查询";
    bl.dataset.alert = "false";
  } else {
    // Only genuine abuse listings turn this row red. A policy listing (PBL on
    // a mobile/residential range) is normal and is shown in plain text so the
    // user knows it was seen without it reading as a warning.
    const parts: string[] = [];
    if (s.blacklistHits.length > 0) {
      parts.push(`${s.blacklistHits.length} 命中: ${s.blacklistHits.join(", ")}`);
    } else {
      parts.push(`0 / ${s.blacklistChecked} 命中`);
    }
    if (s.blacklistPolicy.length > 0) {
      parts.push(`(${s.blacklistPolicy.length} 条策略命中)`);
    }
    bl.textContent = parts.join(" ");
    bl.dataset.alert = s.blacklistHits.length > 0 ? "true" : "false";
  }

  // Checks.
  const list = $("check-list");
  list.replaceChildren(
    ...s.checks.map((c) => {
      const row = document.createElement("div");
      row.className = "check";
      row.dataset.ok =
        c.agrees === null ? "unknown" : c.agrees ? "true" : "false";

      const mark = document.createElement("span");
      mark.className = "mark";
      mark.textContent = c.agrees === null ? "?" : c.agrees ? "✓" : "✗";

      const lbl = document.createElement("span");
      lbl.className = "lbl";
      lbl.textContent = c.label;

      const det = document.createElement("span");
      det.className = "det";
      det.textContent = c.detail;

      row.append(mark, lbl, det);
      return row;
    }),
  );

  // Conflicts get their own highlighted block: they mean the line is behaving
  // inconsistently, which no single number can express.
  const wrap = $("conflict-wrap");
  if (s.conflicts.length > 0) {
    wrap.classList.remove("hidden");
    $("conflict-list").replaceChildren(
      ...s.conflicts.map((c) => {
        const row = document.createElement("div");
        row.className = "conflict";
        row.textContent = `${c.field}: ${c.a} ↔ ${c.b}`;
        return row;
      }),
    );
  } else {
    wrap.classList.add("hidden");
  }

  // Sources.
  $("source-list").replaceChildren(
    ...s.sources.map((src) => {
      const row = document.createElement("div");
      row.className = "src";
      // Three states, not two: ok, failed, and "not configured". The last one
      // must look deliberate rather than broken, because it is our choice.
      row.dataset.state = src.ok ? "ok" : src.configured ? "failed" : "skipped";

      const nm = document.createElement("span");
      nm.className = "nm";
      nm.textContent = src.name;

      const ms = document.createElement("span");
      ms.className = "ms";
      // A skipped source never ran, so its time is meaningless noise.
      ms.textContent = src.configured ? `${src.tookMs}ms` : "";

      const nt = document.createElement("span");
      nt.className = "nt";
      nt.textContent = src.note;

      row.append(nm, ms, nt);
      return row;
    }),
  );

  $("f-stamp").textContent = relativeTime(s.fetchedAt);
  const badge = $("f-conflicts");
  if (s.conflicts.length > 0) {
    badge.classList.remove("hidden");
    badge.textContent = `⚠ ${s.conflicts.length} 源冲突`;
  } else {
    badge.classList.add("hidden");
  }
}

function applyUpdate(u: Update): void {
  lastSnapshot = u.snapshot;

  const err = $("e-error");
  if (u.error) {
    err.classList.remove("hidden");
    err.textContent = u.error;
  } else {
    err.classList.add("hidden");
  }

  renderCollapsed(u.snapshot);
  if (expanded) {
    renderExpanded(u.snapshot);
    // Content height changes when the check/source lists change, so the window
    // has to be re-fitted; otherwise a longer list is silently clipped.
    void fitWindow();
  }

  // The one moment we allow the card to pulse: the risk band moved, which is
  // the difference between "fine" and "look at this".
  if (u.riskBandChanged) {
    const dot = $("c-dot");
    dot.classList.remove("pulse");
    // Force a reflow so the animation restarts if it is already running.
    void dot.offsetWidth;
    dot.classList.add("pulse");
    setTimeout(() => dot.classList.remove("pulse"), 1400);
  }
}

// ------------------------------------------------------------- interaction

const COLLAPSED_W = 260;
const COLLAPSED_H = 52;
const EXPANDED_W = 320;
/** Hard ceiling for the expanded height, in logical pixels. Content taller
 *  than this scrolls rather than running off the screen. */
const EXPANDED_MAX_H = 620;

/// Resize the OS window to exactly fit the card's current content.
///
/// A fixed height was the original approach and it was wrong: the number of
/// leak checks, blacklist rows and sources varies per run, so any constant is
/// either clipping content or leaving a transparent dead zone that swallows
/// clicks meant for the app underneath. Measuring is the only honest option.
async function fitWindow(): Promise<void> {
  const win = getCurrentWindow();
  if (!expanded) {
    lastFitH = -1;
    await win.setSize(new LogicalSize(COLLAPSED_W, COLLAPSED_H));
    return;
  }

  // Width first: wrapping — and therefore height — depends on it, and the
  // window may still be at the collapsed width. Only the width is set here.
  const winW = (await win.innerSize()).width / (await win.scaleFactor());
  if (Math.round(winW) !== EXPANDED_W) {
    await win.setSize(new LogicalSize(EXPANDED_W, EXPANDED_MAX_H));
  }

  // #expanded has no height constraint, so its scrollHeight is the content's
  // natural height *regardless of how tall the window currently is*. That is
  // what makes an accurate measurement possible without first resizing the
  // window to guess. An earlier version jumped to EXPANDED_MAX_H to "make
  // room", which left a transparent dead zone whenever the measured height
  // then matched the previous one and the resize was skipped.
  const contentH = $("expanded").scrollHeight;
  const target = Math.min(Math.max(contentH, 160), EXPANDED_MAX_H);

  // Only scroll when we are genuinely at the ceiling, so the common case has
  // no scrollbar stealing card width.
  document.body.classList.toggle("scrollable", contentH > EXPANDED_MAX_H);

  if (target === lastFitH) return;
  lastFitH = target;
  await win.setSize(new LogicalSize(EXPANDED_W, target));
}

/** Re-fit whenever the content's height can change without a new snapshot
 *  arriving — the sources disclosure opening, a wrapped line appearing, a
 *  font finishing loading. A ResizeObserver catches all of these, including
 *  ones we did not anticipate, which beats enumerating triggers by hand. */
function watchContentHeight(): void {
  let pending: number | undefined;
  const ro = new ResizeObserver(() => {
    // Coalesce bursts: opening <details> fires several times in quick
    // succession, and each setSize is an OS round trip.
    if (pending !== undefined) clearTimeout(pending);
    pending = window.setTimeout(() => {
      pending = undefined;
      if (expanded) void fitWindow();
    }, 60);
  });
  ro.observe($("expanded"));
  // The card is what actually defines the visual extent; observing it as well
  // catches changes that do not alter #expanded's own box.
  ro.observe($("expanded").parentElement ?? document.body);
}

async function setExpanded(on: boolean): Promise<void> {
  expanded = on;
  $("collapsed").classList.toggle("hidden", on);
  $("expanded").classList.toggle("hidden", !on);

  // Reset the memo so the first fit after a collapse/expand actually applies;
  // otherwise re-expanding to the same height as last time would be skipped.
  lastFitH = -1;
  if (on && lastSnapshot) renderExpanded(lastSnapshot);
  await fitWindow();
}

async function doRefresh(): Promise<void> {
  if (refreshing) return;
  refreshing = true;
  const btn = $("btn-refresh");
  btn.classList.add("spin");
  try {
    const u = await invoke<Update>("force_refresh");
    applyUpdate(u);
  } catch (e) {
    const err = $("e-error");
    err.classList.remove("hidden");
    err.textContent = `刷新失败: ${String(e)}`;
  } finally {
    refreshing = false;
    btn.classList.remove("spin");
  }
}

function wireUp(): void {
  $("collapsed").addEventListener("click", () => {
    if (suppressNextClick) return;
    void setExpanded(true);
  });
  $("btn-collapse").addEventListener("click", (e) => {
    e.stopPropagation();
    void setExpanded(false);
  });
  $("btn-refresh").addEventListener("click", (e) => {
    e.stopPropagation();
    void doRefresh();
  });
  $("btn-copy").addEventListener("click", async (e) => {
    e.stopPropagation();
    if (!lastSnapshot) return;
    try {
      await navigator.clipboard.writeText(lastSnapshot.ip);
      const btn = $("btn-copy");
      btn.textContent = "✓";
      setTimeout(() => (btn.textContent = "⧉"), 1100);
    } catch {
      /* clipboard may be unavailable; nothing useful to tell the user */
    }
  });

  // Dragging by the card body, using Tauri's own startDragging so the OS
  // handles snapping, DPI and multi-monitor correctly.
  //
  // A naive `mousedown -> startDragging()` breaks clicking entirely: the OS
  // begins a drag on press, so the matching `click` never lands and the card
  // can never be expanded (observed during testing — every click turned into a
  // small window move). So a drag only starts once the pointer has actually
  // moved past a small threshold with the button still held; a press that ends
  // without movement is left alone and fires `click` normally.
  const DRAG_THRESHOLD_PX = 4;
  const dragTargets = [$("collapsed"), document.querySelector("header")];
  for (const el of dragTargets) {
    el?.addEventListener("mousedown", (e) => {
      if (e.button !== 0) return;
      if ((e.target as HTMLElement).closest("button")) return;

      const startX = e.clientX;
      const startY = e.clientY;
      let started = false;

      const onMove = (ev: MouseEvent) => {
        if (started) return;
        const dx = Math.abs(ev.clientX - startX);
        const dy = Math.abs(ev.clientY - startY);
        if (dx < DRAG_THRESHOLD_PX && dy < DRAG_THRESHOLD_PX) return;
        started = true;
        // The OS drag swallows the pointerup, so the browser may still emit a
        // click afterwards; flag it so the expand handler ignores that one.
        suppressNextClick = true;
        setTimeout(() => (suppressNextClick = false), 400);
        cleanup();
        void getCurrentWindow().startDragging();
      };

      const cleanup = () => {
        window.removeEventListener("mousemove", onMove);
        window.removeEventListener("mouseup", onUp);
      };

      const onUp = () => cleanup();

      window.addEventListener("mousemove", onMove);
      window.addEventListener("mouseup", onUp);
    });
  }
}

// -------------------------------------------------------------------- boot

async function main(): Promise<void> {
  wireUp();
  watchContentHeight();

  // Push updates from the background refresh loop.
  await listen<Update>("ipcheck://update", (event) => {
    applyUpdate(event.payload);
  });

  try {
    const initial = await invoke<Update>("get_snapshot");
    applyUpdate(initial);
  } catch (e) {
    $("c-ip").textContent = "初始化失败";
    console.error("get_snapshot failed", e);
  }

  // Keep the "N 分钟前" stamp honest while the card sits open.
  setInterval(() => {
    if (expanded && lastSnapshot) {
      $("f-stamp").textContent = relativeTime(lastSnapshot.fetchedAt);
    }
  }, 15_000);

  await setExpanded(false);
}

void main();
