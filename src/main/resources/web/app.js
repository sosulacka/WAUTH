"use strict";

const $ = id => document.getElementById(id);
const url = new URL(location.href);
const TOKEN = new URLSearchParams(url.hash.slice(1)).get("token") || url.searchParams.get("token") || "";
if (url.searchParams.has("token")) {
    url.searchParams.delete("token");
    url.hash = new URLSearchParams({ token: TOKEN }).toString();
    history.replaceState(null, "", url.pathname + url.search + url.hash);
}
const PROVIDERS = { DISCORD: "Discord", TELEGRAM: "Telegram", VK: "VK" };
let generation = 0;
let pollTimer;
let countdown;
let toastTimer;
let expiry = 0;
let clockOffset = 0;
let backupCodes = [];
let phase = 1;
let activeView = "loading";

function show(name) {
    activeView = name;
    for (const key of ["loading", "link", "done", "error"]) $("view-" + key).hidden = key !== name;
    const title = $(name + "-title");
    if (title && title.hasAttribute("tabindex")) title.focus({ preventScroll: true });
}

function step(number) {
    phase = number;
    for (let i = 1; i <= 3; i++) {
        const el = $("step-" + i);
        el.classList.toggle("is-complete", i < number);
        if (i === number) el.setAttribute("aria-current", "step");
        else el.removeAttribute("aria-current");
    }
}

function stop() {
    generation++;
    clearTimeout(pollTimer);
    clearInterval(countdown);
}

function error(kind) {
    stop();
    const network = kind === "network";
    $("error-title").textContent = network ? "Не удалось связаться с сервером" : "Нужна новая ссылка";
    $("error-description").textContent = network
        ? "Проверьте подключение к интернету и повторите попытку. Ваша настройка пока не завершена."
        : "Ссылка отсутствует, истекла или была отозвана. Вернитесь в игру и введите /2fa link, чтобы получить новую.";
    $("retry").hidden = !network;
    $("panel-indicator").textContent = network ? "Нет соединения" : "Сессия недоступна";
    show("error");
}

async function request(path) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
        const response = await fetch(path, {
            headers: { Authorization: `Bearer ${TOKEN}`, Accept: "application/json" },
            cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer", signal: controller.signal
        });
        if ([400, 401, 403, 404, 410].includes(response.status)) throw new Error("expired");
        if (!response.ok) throw new Error("network");
        const serverDate = Date.parse(response.headers.get("Date") || "");
        if (Number.isFinite(serverDate)) clockOffset = serverDate - Date.now();
        return await response.json();
    } finally {
        clearTimeout(timeout);
    }
}

async function boot() {
    stop();
    const run = generation;
    show("loading");
    step(1);
    if (!TOKEN || TOKEN.length > 512) return error("expired");
    try {
        const info = await request("/api/setup/info");
        if (run !== generation) return;
        if (typeof info.code !== "string" || !Number.isFinite(info.expiresAt)) throw new Error("network");
        $("player-name").textContent = info.playerName || "Игрок";
        $("link-code").textContent = info.code;
        expiry = info.expiresAt;
        setWaiting(false);
        show("link");
        if (!tick()) return;
        countdown = setInterval(tick, 1000);
        poll(run, 0);
    } catch (failure) {
        if (run === generation) error(failure.message === "expired" ? "expired" : "network");
    }
}

function tick() {
    const left = expiry - Date.now() - clockOffset;
    if (left <= 0) { error("expired"); return false; }
    const seconds = Math.ceil(left / 1000);
    $("code-timer").textContent = `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
    return true;
}

function setWaiting(confirm) {
    step(confirm ? 2 : 1);
    $("link-eyebrow").textContent = confirm ? "Шаг 02 / 03" : "Шаг 01 / 03";
    $("link-title").textContent = confirm ? "Подтвердите в игре" : "Начнём с кода";
    $("link-description").textContent = confirm
        ? "Бот принял код. Осталось подтвердить, что аккаунт привязываете именно вы."
        : "Скопируйте код и отправьте его нашему боту в Telegram.";
    $("code-area").hidden = confirm;
    $("open-bot").hidden = confirm;
    $("bot-handle").hidden = confirm;
    $("confirm-hint").hidden = !confirm;
    $("panel-indicator").textContent = confirm ? "Ожидаем подтверждение" : "Сессия активна";
    $("status-dot").classList.remove("offline");
    $("connection-status").textContent = confirm
        ? "Ждём подтверждение в игре. Статус обновится автоматически."
        : "Ждём отправку кода. Обновлять страницу не нужно.";
}

async function poll(run, failures) {
    try {
        const status = await request("/api/setup/status");
        if (run !== generation) return;
        if (status.linked === true) { linked(status); return; }
        setWaiting(status.needsConfirm === true);
        failures = 0;
    } catch (failure) {
        if (run !== generation) return;
        if (failure.message === "expired") { error("expired"); return; }
        failures++;
        $("status-dot").classList.add("offline");
        $("panel-indicator").textContent = "Восстанавливаем связь";
        $("connection-status").textContent = "Связь с сервером прервалась. Пробуем подключиться снова…";
    }
    if (run === generation) pollTimer = setTimeout(() => poll(run, failures), Math.min(15000, 2500 * (failures + 1)));
}

function linked(status) {
    stop();
    step(3);
    $("panel-indicator").textContent = "Защита подключена";
    $("done-provider").textContent = PROVIDERS[status.provider] || "Мессенджер";
    backupCodes = Array.isArray(status.backup) ? status.backup.filter(code => typeof code === "string") : [];
    $("backup-grid").replaceChildren();
    for (const code of backupCodes) {
        const item = document.createElement("div");
        item.className = "backup-code";
        item.textContent = code;
        $("backup-grid").appendChild(item);
    }
    $("backup-wrap").hidden = !backupCodes.length;
    $("backup-unavailable").hidden = !!backupCodes.length;
    $("completion").hidden = true;
    show("done");
}

function notify(message) {
    $("toast").textContent = message;
    $("toast").hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { $("toast").hidden = true; }, 5000);
}

async function copy(text, element) {
    try {
        if (!navigator.clipboard) throw new Error("clipboard unavailable");
        await navigator.clipboard.writeText(text);
        notify("Скопировано. Сохраните код в надёжном месте.");
    } catch {
        const selection = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(element);
        selection.removeAllRanges();
        selection.addRange(range);
        notify("Браузер запретил копирование. Код выделен, скопируйте его вручную.");
    }
}

$("copy-code").addEventListener("click", () => copy($("link-code").textContent, $("link-code")));
$("copy-backup").addEventListener("click", () => copy(backupCodes.join("\n"), $("backup-grid")));
$("retry").addEventListener("click", boot);
$("saved-codes").addEventListener("change", event => {
    $("completion").hidden = !event.target.checked;
    step(event.target.checked ? 4 : 3);
});
window.addEventListener("pagehide", stop);
window.addEventListener("pageshow", event => { if (event.persisted && activeView !== "done") boot(); });
boot();
