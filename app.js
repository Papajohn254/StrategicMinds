const API_BASE = "";

function getStoredItem(key){
  // Prefer session auth when present, otherwise fall back to persistent auth.
  const sessionValue = sessionStorage.getItem(key);
  if(sessionValue !== null && sessionValue !== undefined) return sessionValue;
  return localStorage.getItem(key);
}

function setStoredItem(key, value, remember){
  const storage = remember ? localStorage : sessionStorage;
  storage.setItem(key, value);
}

function removeStoredItem(key){
  sessionStorage.removeItem(key);
  localStorage.removeItem(key);
}

function getToken(){
  return getStoredItem("token");
}

function getCurrentUser(){
  try{
    return JSON.parse(getStoredItem("currentUser") || "null");
  }catch(e){
    return null;
  }
}

function setSession(user, token, remember = true){
  // Reset any existing session first to avoid mixed storage state.
  clearSession();

  setStoredItem("token", token, remember);
  setStoredItem("currentUser", JSON.stringify(user), remember);
  setStoredItem("isLoggedIn", "true", remember);
  if(user && user.branch_id){
    localStorage.setItem("activeBranchId", String(user.branch_id));
  }
}

function clearSession(){
  removeStoredItem("token");
  removeStoredItem("currentUser");
  removeStoredItem("isLoggedIn");
  localStorage.removeItem("activeBranchId");
}

async function apiFetch(path, options={}){
  const token = getToken();
  const headers = options.headers || {};
  if(!(options.body instanceof FormData)){
    headers["Content-Type"] = headers["Content-Type"] || "application/json";
  }
  if(token){
    headers["Authorization"] = `Bearer ${token}`;
  }
  const res = await fetch(API_BASE + path, { ...options, headers });
  if(res.status === 401){
    clearSession();
    window.location.href = "index.html";
    throw new Error("Unauthorized");
  }
  return res;
}

function nav(page){
  window.location.href = page;
}

function addGlobalMobileStyles(){
  const style = document.createElement('style');
  style.id = 'global-mobile-hamburger-styles';
  style.textContent = `
    .mobile-global-sidebar-hidden .sidebar { display: none !important; }
    .mobile-global-sidebar-hidden .main, .mobile-global-sidebar-hidden .content, .mobile-global-sidebar-hidden .page-wrapper {
      width: 100% !important;
      max-width: 100% !important;
      margin: 0 !important;
      padding: 12px !important;
    }
    @media (max-width: 992px) {
      .sidebar { display: none !important; }
      .main, .content, .page-wrapper { width: 100% !important; max-width: 100% !important; margin: 0 !important; padding: 12px !important; }
      .topbar { padding: 12px 12px; }
      .card { margin-bottom: 14px; }
    }
    @media (max-width: 768px) {
      .hamburger-btn { display: flex !important; }
    }
  `;
  if(!document.getElementById('global-mobile-hamburger-styles')){
    document.head.appendChild(style);
  }
}

async function loadHamburgerComponent(){
  if(document.getElementById('sidebarMenu')) return;
  try {
    const res = await fetch('components/hamburger-menu.html', { cache: 'no-store' });
    if(!res.ok) return;
    const html = await res.text();
    const container = document.createElement('div');
    container.innerHTML = html;

    // Execute inline scripts in component
    const scripts = Array.from(container.querySelectorAll('script'));
    scripts.forEach(script => {
      const s = document.createElement('script');
      if(script.src){ s.src = script.src; } else { s.textContent = script.textContent; }
      document.body.appendChild(s);
    });

    // Remove scripts from container before append to avoid duplicate execution
    scripts.forEach(s => s.remove());

    // Prepend markup so the menu is available globally
    document.body.prepend(container);

  }catch(err){
    console.warn('Unable to load hamburger component:', err);
  }
}

function initGlobalHamburger(){
  // if there is already a sidebar from the existing template, hide it on mobile
  addGlobalMobileStyles();
  if(window.innerWidth <= 992){
    document.body.classList.add('mobile-global-sidebar-hidden');
  }

  window.addEventListener('resize', () => {
    if(window.innerWidth <= 992){
      document.body.classList.add('mobile-global-sidebar-hidden');
    }else{
      document.body.classList.remove('mobile-global-sidebar-hidden');
    }
  });

  loadHamburgerComponent();
}

function injectNavItems(){
  const sidebars = document.querySelectorAll(".sidebar ul");
  if(sidebars.length === 0) return;
  const items = [
    { id: "navAI", label: "AI Command Center", page: "ai-center.html" },
    { id: "navBiometric", label: "Biometric", page: "biometric.html" },
    { id: "navVendorPortal", label: "Vendor Portal", page: "vendor-portal.html" },
    { id: "navNotifications", label: "Notifications", page: "messages.html#notifications" },
    { id: "navMessages", label: "Messages", page: "messages.html" },
    { id: "navWarehouses", label: "Warehouses", page: "warehouses.html" },
    { id: "navDelivery", label: "Delivery", page: "delivery.html" }
  ];
  sidebars.forEach(ul => {
    const logoutItem = Array.from(ul.querySelectorAll("li")).find(li => li.textContent && li.textContent.toLowerCase().includes("logout"));
    items.forEach(item => {
      if(document.getElementById(item.id)) return;
      const li = document.createElement("li");
      li.id = item.id;
      li.textContent = item.label;
      li.addEventListener("click", () => nav(item.page));
      if(logoutItem){
        ul.insertBefore(li, logoutItem);
      }else{
        ul.appendChild(li);
      }
    });
  });
}

async function logout(){
  try{
    await apiFetch("/api/auth/logout", { method: "POST" });
  }catch(e){
    // ignore logout errors
  }
  clearSession();
  window.location.href = "index.html";
}

function applyUserContext(allowedRoles){
  const token = getToken();
  const currentUser = getCurrentUser();
  if(!token || !currentUser){
    window.location.href = "index.html";
    return null;
  }
  injectNavItems();
  initGlobalHamburger();
  if(allowedRoles && !allowedRoles.includes(currentUser.role)){
    alert("Access denied.");
    const role = String(currentUser.role || "").toLowerCase();
    if(role === "rider"){
      window.location.href = "delivery.html";
    }else if(role === "cashier"){
      window.location.href = "sales.html";
    }else{
      window.location.href = "dashboard.html";
    }
    return null;
  }
  const badge = document.getElementById("userBadge");
  if(badge){
    badge.innerText = `👤 ${currentUser.name} (${currentUser.role})`;
  }
  const navPermissions = {
    navDashboard:["admin","manager","staff","cashier","supervisor","storekeeper"],
    navProducts:["admin","manager"],
    navSuppliers:["admin","manager"],
    navInventory:["admin","manager","staff","storekeeper"],
    navCustomers:["admin","manager","staff","cashier"],
    navSales:["admin","manager","cashier","staff"],
    navReceipts:["admin","manager","supervisor","cashier"],
    navReturns:["admin","manager","supervisor","cashier"],
    navShopfront:["admin","manager","supervisor","staff","cashier","storekeeper"],
    navKitchen:["admin","manager","supervisor","storekeeper","cashier"],
    navFeedback:["admin","manager","supervisor","staff","cashier","storekeeper"],
    navReferrals:["admin","manager","supervisor","staff","cashier","storekeeper"],
    navRequests:["admin","manager","supervisor","staff","cashier","storekeeper"],
    navUsers:["admin"],
    navReports:["admin","manager","supervisor"],
    navBranches:["admin","manager"],
    navAttendance:["admin","manager","supervisor"],
    navSettings:["admin","manager"],
    navAI:["admin","manager","supervisor"],
    navBiometric:["admin","manager","supervisor","staff","cashier","storekeeper"],
    navVendorPortal:["supplier","seller","retailer","wholesaler"],
    navWarehouses:["admin","manager"],
    navNotifications:["admin","manager","supervisor","staff","cashier","storekeeper","rider"],
    navMessages:["admin","manager","supervisor","staff","cashier","storekeeper","rider"],
    navDelivery:["admin","manager","supervisor","rider"]
  };
  Object.keys(navPermissions).forEach(id=>{
    const el = document.getElementById(id);
    if(el && !navPermissions[id].includes(currentUser.role)){
      el.style.display = "none";
    }
  });
  initUnreadIndicators();
  return currentUser;
}

let unreadIndicatorsStarted = false;

function ensureUnreadIndicatorStyles(){
  if(document.getElementById("unreadIndicatorStyles")) return;
  const style = document.createElement("style");
  style.id = "unreadIndicatorStyles";
  style.textContent = `
    .nav-unread-badge{
      margin-left:auto;
      min-width:18px;
      height:18px;
      padding:0 6px;
      border-radius:999px;
      background:#ef4444;
      color:#fff;
      font-size:10px;
      font-weight:700;
      display:none;
      align-items:center;
      justify-content:center;
      line-height:1;
      box-shadow:0 0 0 2px rgba(255,255,255,0.12);
    }
  `;
  document.head.appendChild(style);
}

function ensureNavUnreadBadge(navId, badgeId){
  const nav = document.getElementById(navId);
  if(!nav) return null;
  let badge = document.getElementById(badgeId);
  if(badge) return badge;
  badge = document.createElement("span");
  badge.id = badgeId;
  badge.className = "nav-unread-badge";
  nav.appendChild(badge);
  return badge;
}

function updateUnreadBadgeElement(elementId, count){
  const badge = document.getElementById(elementId);
  if(!badge) return;
  const total = Number(count) || 0;
  if(total > 0){
    badge.textContent = total > 99 ? "99+" : String(total);
    badge.style.display = "inline-flex";
  }else{
    badge.style.display = "none";
  }
}

async function refreshUnreadIndicators(){
  const token = getToken();
  if(!token) return;
  try{
    const [summaryRes, notificationRes] = await Promise.all([
      apiFetch("/api/dashboard/summary"),
      apiFetch("/api/notifications?status=unread")
    ]);
    if(!summaryRes.ok || !notificationRes.ok) return;
    const summary = await summaryRes.json();
    const notifications = await notificationRes.json();
    const unreadMessages = Number(summary && summary.unreadMessages) || 0;
    const unreadNotifications = Number(summary && summary.unreadNotifications);
    const notificationCount = Number.isFinite(unreadNotifications)
      ? unreadNotifications
      : (Array.isArray(notifications) ? notifications.length : 0);

    updateUnreadBadgeElement("navMessagesBadge", unreadMessages);
    updateUnreadBadgeElement("messagesBadge", unreadMessages);
    updateUnreadBadgeElement("navNotificationsBadge", notificationCount);
    updateUnreadBadgeElement("notificationsBadge", notificationCount);
  }catch(e){
    // ignore indicator refresh errors
  }
}

function initUnreadIndicators(){
  ensureUnreadIndicatorStyles();
  ensureNavUnreadBadge("navMessages", "navMessagesBadge");
  ensureNavUnreadBadge("navNotifications", "navNotificationsBadge");
  refreshUnreadIndicators();
  if(unreadIndicatorsStarted) return;
  unreadIndicatorsStarted = true;
  setInterval(() => {
    if(document.visibilityState === "visible"){
      refreshUnreadIndicators();
    }
  }, 15000);
}

function formatKES(value){
  const n = Number(value) || 0;
  return "KES " + n.toLocaleString();
}

function getActiveBranchId(){
  const raw = localStorage.getItem("activeBranchId");
  if(!raw || raw === "all") return null;
  const id = Number(raw);
  return Number.isFinite(id) ? id : null;
}

function setActiveBranchId(id){
  if(id === "all" || id === null){
    localStorage.setItem("activeBranchId", "all");
    return;
  }
  if(id){
    localStorage.setItem("activeBranchId", String(id));
  }
}

function getActiveBranchParam(){
  const raw = localStorage.getItem("activeBranchId");
  if(!raw) return null;
  if(raw === "all") return "all";
  const id = Number(raw);
  return Number.isFinite(id) ? String(id) : null;
}

async function initBranchSelector(){
  const select = document.getElementById("branchSelect");
  if(!select) return;
  const res = await apiFetch("/api/branches");
  const branches = await res.json();
  const currentUser = getCurrentUser();
  let allowed = branches;
  const allowAll = currentUser && ["admin","manager","supervisor"].includes(currentUser.role);
  if(currentUser && currentUser.branch_id && !allowAll){
    allowed = branches.filter(b => Number(b.id) === Number(currentUser.branch_id));
  }
  select.innerHTML = "";
  if(allowAll){
    const optAll = document.createElement("option");
    optAll.value = "all";
    optAll.textContent = "All Branches";
    select.appendChild(optAll);
  }
  allowed.forEach(b=>{
    const opt = document.createElement("option");
    opt.value = b.id;
    opt.textContent = b.name;
    select.appendChild(opt);
  });
  let activeRaw = localStorage.getItem("activeBranchId");
  if(!activeRaw || (!allowAll && activeRaw === "all")){
    activeRaw = currentUser && currentUser.branch_id ? String(currentUser.branch_id) : (allowAll ? "all" : (allowed[0] ? String(allowed[0].id) : null));
    if(activeRaw) setActiveBranchId(activeRaw);
  }
  if(activeRaw && (activeRaw === "all" || allowed.find(b => String(b.id) === String(activeRaw)))){
    select.value = activeRaw;
  }
  if(currentUser && currentUser.branch_id && !allowAll) select.disabled = true;

  select.addEventListener("change", ()=>{
    const value = select.value;
    if(value === "all"){
      setActiveBranchId("all");
    }else{
      const id = Number(value);
      if(Number.isFinite(id)) setActiveBranchId(id);
    }
    if(typeof window.onBranchChange === "function"){
      const active = getActiveBranchId();
      window.onBranchChange(active);
    }
    if(typeof window.refreshAnnouncement === "function"){
      window.refreshAnnouncement();
    }
    if(typeof window.refreshSiteFooter === "function"){
      window.refreshSiteFooter();
    }
  });
}

function initAnnouncementBar(){
  if(document.getElementById("announcementBar")) return;
  const styleId = "announcementStyles";
  if(!document.getElementById(styleId)){
    const style = document.createElement("style");
    style.id = styleId;
    style.textContent = `
    #announcementBar{background:#1e2f37;color:#fff;font-size:13px;letter-spacing:0.2px;overflow:hidden;border-bottom:1px solid rgba(255,255,255,0.12);z-index:5;}
    #announcementBar.fixed{position:fixed;left:0;right:0;top:0;}
    #announcementBar.in-main{position:sticky;top:0;}
    #announcementBar .announcement-track{display:inline-block;white-space:nowrap;padding-left:100%;animation:announcement-marquee 22s linear infinite;}
    #announcementBar .announcement-text{display:inline-block;padding:6px 40px;}
    @keyframes announcement-marquee{0%{transform:translateX(0);}100%{transform:translateX(-100%);}}
    `;
    document.head.appendChild(style);
  }

  const bar = document.createElement("div");
  bar.id = "announcementBar";
  bar.innerHTML = `<div class="announcement-track"><span class="announcement-text"></span></div>`;

  const main = document.querySelector(".main");
  if(main){
    bar.classList.add("in-main");
    main.insertBefore(bar, main.firstChild);
  }else{
    bar.classList.add("fixed");
    document.body.appendChild(bar);
    document.body.style.paddingTop = "32px";
  }

  const track = bar.querySelector(".announcement-track");
  const textEl = bar.querySelector(".announcement-text");
  const defaults = {
    announcement_text: "Welcome to SmartInventory Pro — Modern POS & Inventory for every branch.",
    announcement_enabled: true,
    announcement_speed: 22
  };

  function applyAnnouncement(settings){
    const merged = { ...defaults, ...(settings || {}) };
    const enabled = merged.announcement_enabled !== false;
    const text = String(merged.announcement_text || "").trim();
    if(!enabled || !text){
      bar.style.display = "none";
      return;
    }
    bar.style.display = "block";
    textEl.textContent = text;
    const speed = Math.max(8, Math.min(60, Number(merged.announcement_speed) || defaults.announcement_speed));
    track.style.animationDuration = `${speed}s`;
  }

  window.refreshAnnouncement = async function(){
    const token = getToken();
    if(!token){
      applyAnnouncement(defaults);
      return;
    }
    try{
      const branchParam = getActiveBranchParam();
      const res = await apiFetch(branchParam ? `/api/settings?branch_id=${branchParam}` : "/api/settings");
      const data = await res.json();
      applyAnnouncement(data || {});
    }catch(err){
      applyAnnouncement(defaults);
    }
  };

  window.refreshAnnouncement();
}

try{
  initAnnouncementBar();
}catch(e){
  // ignore init errors
}

function initNotificationBell(){
  if(document.getElementById("notificationBell")) return;
  const token = getToken();
  if(!token) return;

  const target = document.querySelector(".topbar-right") || document.querySelector(".topbar");
  if(!target) return;

  const styleId = "notificationBellStyles";
  if(!document.getElementById(styleId)){
    const style = document.createElement("style");
    style.id = styleId;
    style.textContent = `
      #notificationBell{position:relative;border:1px solid var(--line,#e6e2dc);background:#fff;border-radius:999px;padding:6px 10px;font-size:12px;cursor:pointer;display:flex;align-items:center;gap:6px;}
      #notificationBell .badge{background:#ef4444;color:#fff;font-size:10px;padding:2px 6px;border-radius:999px;min-width:18px;text-align:center;}
      #notificationPanel{position:fixed;top:72px;right:24px;width:320px;max-height:420px;background:#fff;border-radius:14px;box-shadow:0 18px 40px rgba(15,23,42,0.18);overflow:hidden;display:none;flex-direction:column;z-index:999;}
      #notificationPanel.open{display:flex;}
      #notificationPanel .panel-head{display:flex;align-items:center;justify-content:space-between;padding:12px 14px;border-bottom:1px solid #eef2f5;font-size:13px;font-weight:600;}
      #notificationPanel .panel-body{padding:10px;display:grid;gap:10px;overflow:auto;}
      .notification-item{border:1px solid #eef2f5;background:#f9fafb;border-radius:12px;padding:10px;cursor:pointer;display:grid;gap:6px;font-size:12px;}
      .notification-item.unread{border-color:rgba(14,165,164,0.4);background:#f1fbfa;}
      .notification-meta{color:#6b7280;font-size:11px;}
      .notification-empty{padding:16px;color:#6b7280;text-align:center;font-size:12px;}
      #notificationPanel .panel-actions{display:flex;gap:8px;padding:10px;border-top:1px solid #eef2f5;}
      #notificationPanel .panel-actions button{flex:1;padding:8px 10px;border-radius:10px;border:none;cursor:pointer;font-size:12px;}
      #notificationPanel .panel-actions .view-all{background:#0ea5a4;color:#fff;}
      #notificationPanel .panel-actions .mark-read{background:#e2f4f3;color:#0f766e;}
    `;
    document.head.appendChild(style);
  }

  const bell = document.createElement("button");
  bell.id = "notificationBell";
  bell.type = "button";
  bell.innerHTML = `<span>Alerts</span><span class="badge" id="notificationBadge">0</span>`;

  const panel = document.createElement("div");
  panel.id = "notificationPanel";
  panel.innerHTML = `
    <div class="panel-head">
      <span>Notifications</span>
      <button type="button" id="closeNotifications" style="border:none;background:transparent;cursor:pointer;font-size:14px;">x</button>
    </div>
    <div class="panel-body" id="notificationPanelBody"></div>
    <div class="panel-actions">
      <button type="button" class="mark-read" id="markAllNotifications">Mark all read</button>
      <button type="button" class="view-all" id="viewAllNotifications">View all</button>
    </div>
  `;

  target.prepend(bell);
  document.body.appendChild(panel);

  const badge = panel.ownerDocument.getElementById("notificationBadge");
  const panelBody = panel.ownerDocument.getElementById("notificationPanelBody");

  let panelOpen = false;
  let lastUnread = 0;

  async function fetchNotifications(status){
    const url = status ? `/api/notifications?status=${status}` : "/api/notifications";
    const res = await apiFetch(url);
    return res.json();
  }

  function renderPanel(list){
    if(!Array.isArray(list) || list.length === 0){
      panelBody.innerHTML = `<div class="notification-empty">No notifications yet.</div>`;
      return;
    }
    panelBody.innerHTML = "";
    list.slice(0, 8).forEach(item => {
      const card = document.createElement("div");
      card.className = `notification-item ${item.status === "unread" ? "unread" : ""}`;
      const title = item.title ? `<strong>${item.title}</strong>` : `<strong>${item.type}</strong>`;
      card.innerHTML = `
        ${title}
        <div>${item.message}</div>
        <div class="notification-meta">${new Date(item.created_at).toLocaleString()}</div>
      `;
      card.addEventListener("click", async () => {
        if(item.status === "unread"){
          await apiFetch("/api/notifications/mark-read", { method: "POST", body: JSON.stringify({ id: item.id }) });
        }
        if(item.link){
          window.location.href = item.link;
        }
        refreshUnread();
        if(panelOpen) openPanel();
      });
      panelBody.appendChild(card);
    });
  }

  async function refreshUnread(){
    try{
      const unread = await fetchNotifications("unread");
      lastUnread = unread.length;
      badge.textContent = String(lastUnread);
      badge.style.display = lastUnread > 0 ? "inline-block" : "none";
      if(panelOpen) renderPanel(unread);
    }catch(e){
      // ignore
    }
  }

  async function openPanel(){
    panelOpen = true;
    panel.classList.add("open");
    const list = await fetchNotifications();
    renderPanel(list);
  }

  function closePanel(){
    panelOpen = false;
    panel.classList.remove("open");
  }

  bell.addEventListener("click", () => {
    if(panelOpen){
      closePanel();
    }else{
      openPanel();
    }
  });

  panel.querySelector("#closeNotifications").addEventListener("click", closePanel);
  panel.querySelector("#viewAllNotifications").addEventListener("click", () => {
    window.location.href = "messages.html#notifications";
  });
  panel.querySelector("#markAllNotifications").addEventListener("click", async () => {
    await apiFetch("/api/notifications/mark-read", { method: "POST", body: JSON.stringify({ all: true }) });
    refreshUnread();
    if(panelOpen) openPanel();
  });

  refreshUnread();
  setInterval(() => {
    if(document.visibilityState === "visible") refreshUnread();
  }, 15000);
}

try{
  initNotificationBell();
}catch(e){
  // ignore init errors
}

function initGlobalFooter(){
  const styleId = "globalSiteFooterStyles";
  if(!document.getElementById(styleId)){
    const style = document.createElement("style");
    style.id = styleId;
    style.textContent = `
      #globalSiteFooter{
        margin-top:auto;
        padding:18px 20px 24px;
        text-align:center;
        font-size:12px;
        color:#64748b;
      }
    `;
    document.head.appendChild(style);
  }

  let footer = document.getElementById("globalSiteFooter");
  if(!footer){
    footer = document.querySelector("footer");
    if(footer){
      footer.id = "globalSiteFooter";
    }
  }
  if(!footer){
    footer = document.createElement("footer");
    footer.id = "globalSiteFooter";
    const main = document.querySelector(".main");
    if(main){
      main.appendChild(footer);
    }else{
      document.body.appendChild(footer);
    }
  }
  footer.textContent = "Copyright © 2026 SmartInventory Pro. All rights reserved.";

  window.refreshSiteFooter = async function(){
    const fallback = "Copyright © 2026 SmartInventory Pro. All rights reserved.";
    try{
      const token = getToken();
      const branchParam = getActiveBranchParam();
      let data = null;
      if(token){
        const url = branchParam ? `/api/settings?branch_id=${branchParam}` : "/api/settings";
        const res = await apiFetch(url);
        data = await res.json();
      }else{
        const query = branchParam && branchParam !== "all" ? `?branch_id=${encodeURIComponent(branchParam)}` : "";
        const res = await fetch(`/api/public/settings${query}`);
        if(res.ok){
          data = await res.json();
        }
      }
      footer.textContent = (data && data.site_footer_text) ? String(data.site_footer_text) : fallback;
    }catch(err){
      footer.textContent = fallback;
    }
  };

  window.refreshSiteFooter();
}

try{
  initGlobalFooter();
}catch(e){
  // ignore footer init errors
}

function initAIHelperWidget(){
  if(document.getElementById("aiHelperWidget")) return;
  const token = getToken();
  if(!token) return;

  const styleId = "aiHelperStyles";
  if(!document.getElementById(styleId)){
    const style = document.createElement("style");
    style.id = styleId;
    style.textContent = `
    #aiHelperWidget{position:fixed;right:20px;bottom:20px;z-index:9999;font-family:'Poppins',sans-serif;}
    #aiHelperButton{background:#2c5364;color:#fff;border:none;border-radius:999px;padding:12px 16px;cursor:pointer;box-shadow:0 6px 16px rgba(0,0,0,0.2);}
    #aiHelperPanel{width:320px;background:#fff;border-radius:14px;box-shadow:0 12px 30px rgba(0,0,0,0.2);overflow:hidden;display:none;flex-direction:column;}
    #aiHelperPanel.open{display:flex;}
    .ai-header{background:#203a43;color:#fff;padding:12px 14px;display:flex;justify-content:space-between;align-items:center;font-size:14px;}
    .ai-body{padding:12px;max-height:280px;overflow:auto;display:grid;gap:10px;background:#f7f9fb;}
    .ai-msg{padding:8px 10px;border-radius:10px;font-size:12px;line-height:1.4;}
    .ai-msg.user{background:#2c5364;color:#fff;justify-self:end;}
    .ai-msg.bot{background:#e9eef2;color:#1f2d36;}
    .ai-suggestions{padding:8px 12px;display:flex;flex-wrap:wrap;gap:6px;background:#fff;border-top:1px solid #eef2f5;}
    .ai-suggestions button{border:1px solid #d7e0e6;background:#fff;color:#2c5364;border-radius:999px;padding:6px 10px;font-size:11px;cursor:pointer;}
    .ai-form{display:flex;gap:8px;padding:10px;border-top:1px solid #eef2f5;background:#fff;}
    .ai-form input{flex:1;padding:8px;border-radius:8px;border:1px solid #ccd6dd;font-size:12px;}
    .ai-form button{padding:8px 12px;border:none;border-radius:8px;background:#2c5364;color:#fff;cursor:pointer;font-size:12px;}
    `;
    document.head.appendChild(style);
  }

  const wrapper = document.createElement("div");
  wrapper.id = "aiHelperWidget";
  wrapper.innerHTML = `
    <button id="aiHelperButton">AI Help</button>
    <div id="aiHelperPanel">
      <div class="ai-header">
        <span>AI Super Assistant</span>
        <button id="aiHelperClose" style="background:none;border:none;color:#fff;font-size:16px;cursor:pointer;">×</button>
      </div>
      <div id="aiHelperMessages" class="ai-body"></div>
      <div id="aiHelperSuggestions" class="ai-suggestions"></div>
      <form id="aiHelperForm" class="ai-form">
        <input id="aiHelperInput" placeholder="Ask anything..." autocomplete="off">
        <button type="submit">Send</button>
      </form>
    </div>
  `;
  document.body.appendChild(wrapper);

  const panel = document.getElementById("aiHelperPanel");
  const button = document.getElementById("aiHelperButton");
  const closeBtn = document.getElementById("aiHelperClose");
  const messages = document.getElementById("aiHelperMessages");
  const form = document.getElementById("aiHelperForm");
  const input = document.getElementById("aiHelperInput");
  const suggestions = document.getElementById("aiHelperSuggestions");

  function addMessage(text, type){
    const msg = document.createElement("div");
    msg.className = `ai-msg ${type}`;
    msg.textContent = text;
    messages.appendChild(msg);
    messages.scrollTop = messages.scrollHeight;
  }

  function buildSuggestions(role){
    const presets = {
      admin: [
        "Show today's sales",
        "Low stock items",
        "Top product this week",
        "Profit summary",
        "Best staff today"
      ],
      manager: [
        "Low stock items",
        "Sales summary today",
        "Staff on duty",
        "Top product",
        "Generate report"
      ],
      cashier: [
        "Price for sugar",
        "How do I process a refund?",
        "Show today's sales",
        "Items running out",
        "Generate receipt"
      ],
      storekeeper: [
        "Items below reorder level",
        "Incoming deliveries",
        "Update stock count",
        "Low stock items",
        "Inventory value"
      ],
      supervisor: [
        "Sales summary today",
        "Staff performance",
        "Late staff today",
        "Low stock items",
        "Profit summary"
      ],
      staff: [
        "Show my performance",
        "Low stock items",
        "Top product",
        "How do I add stock?",
        "Generate report"
      ]
    };
    return presets[role] || presets.staff;
  }

  function renderSuggestions(){
    const user = getCurrentUser();
    const role = user && user.role ? user.role : "staff";
    suggestions.innerHTML = "";
    buildSuggestions(role).forEach(text => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = text;
      btn.addEventListener("click", () => {
        sendQuery(text);
      });
      suggestions.appendChild(btn);
    });
  }

  async function sendQuery(text){
    const query = (text || input.value || "").trim();
    if(!query) return;
    addMessage(query, "user");
    input.value = "";
    try{
      const res = await apiFetch("/api/ai/query", {
        method: "POST",
        body: JSON.stringify({ query, context_page: document.title })
      });
      const data = await res.json();
      if(!res.ok){
        addMessage(data.error || "AI request failed.", "bot");
        return;
      }
      addMessage(data.response || "No response yet.", "bot");
    }catch(err){
      addMessage("Unable to reach AI service.", "bot");
    }
  }

  button.addEventListener("click", () => {
    panel.classList.toggle("open");
    if(panel.classList.contains("open")){
      renderSuggestions();
      input.focus();
    }
  });

  closeBtn.addEventListener("click", () => panel.classList.remove("open"));

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    sendQuery();
  });

  window.openAIHelper = () => {
    panel.classList.add("open");
    renderSuggestions();
    input.focus();
  };
}

try{
  initAIHelperWidget();
}catch(e){
  // ignore init errors
}
