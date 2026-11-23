// config.js — MAX SHOP configuration
// Load this BEFORE data.js on every page: <script src="config.js"></script>
// ─────────────────────────────────────────────────────────────────────────────
const CONFIG = (() => {

  const LOGO_PATH     = "assets/logo.png";
  const SHOP_NAME     = "MAX SHOP";
  const FOOTER_TEXT   = "MAX SHOP © 2025 — Account Generator";

  const SERVICE_LOGOS = {
    discord:       "assets/services/discord.png",
    steam:         "assets/services/steam.png",
    rockstar:      "assets/services/rockstar.png",
    rockstar_code: "assets/services/rockstar.png",
  };

  const DAILY_LIMIT = 40;
  const MAX_PER_GEN = 10;

  const DISCORD_API = "https://japi.rest/discord/v1/user";
  const DISCORD_API_TIMEOUT_MS = 8000;
  async function fetchDiscordUser(id) {
    if (!/^\d{15,20}$/.test(String(id || ""))) throw new Error("Invalid Discord ID");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DISCORD_API_TIMEOUT_MS);
    try { return await fetch(`${DISCORD_API}/${encodeURIComponent(id)}`, { signal: controller.signal }); }
    finally { clearTimeout(timer); }
  }

  const PLAN_LABEL = "WEEKLY · 7 DAYS";
  const PLAN_DAYS  = 7;

  function applyLogos() {
    document.querySelectorAll(".nav-brand-icon img, .brand-icon img").forEach(img => {
      img.src = LOGO_PATH;
      img.onerror = function () {
        this.style.display = "none";
        if (!this.parentNode.dataset.fbSet) {
          this.parentNode.dataset.fbSet = "1";
          this.parentNode.insertAdjacentText("beforeend", "⚡");
        }
      };
    });

    document.querySelectorAll(".nav-brand").forEach(el => {
      if (el.dataset.logoInjected) return;
      el.dataset.logoInjected = "1";
      const img = document.createElement("img");
      img.src   = LOGO_PATH;
      img.alt   = SHOP_NAME;
      img.style.cssText = "width:22px;height:22px;object-fit:contain;filter:unset;vertical-align:middle;margin-right:4px";
      img.onerror = function () { this.remove(); };
      el.prepend(img);
    });

    document.querySelectorAll("img.svc-logo[src='']").forEach(img => {
      const card = img.closest(".card");
      if (!card) return;
      const title = card.querySelector(".card-title")?.textContent || "";
      let src = "";
      if (/discord/i.test(title))  src = SERVICE_LOGOS.discord;
      if (/steam/i.test(title))    src = SERVICE_LOGOS.steam;
      if (/rockstar/i.test(title)) src = SERVICE_LOGOS.rockstar;
      if (src) { img.src = src; img.onerror = function () { this.style.display = "none"; }; }
    });

    const foot = document.querySelector("footer");
    if (foot && FOOTER_TEXT) foot.textContent = FOOTER_TEXT;
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", applyLogos);
  } else {
    applyLogos();
  }

  return {
    LOGO_PATH, SHOP_NAME, FOOTER_TEXT, SERVICE_LOGOS,
    DAILY_LIMIT, MAX_PER_GEN, DISCORD_API, DISCORD_API_TIMEOUT_MS, fetchDiscordUser, PLAN_LABEL, PLAN_DAYS,
  };
})();