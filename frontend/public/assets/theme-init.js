// Theme before first paint (no flash): stored choice wins,
// otherwise Auto — light from 07:00 to 19:00 local, dark at night.
// External file on purpose: the site's CSP is script-src 'self'
// with no 'unsafe-inline', so an inline bootstrap would be blocked.
(function () {
  try {
    var mode = localStorage.getItem("aegis-theme") || "auto";
    var h = new Date().getHours();
    var dark = mode === "dark" || (mode === "auto" && (h < 7 || h >= 19));
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    document.documentElement.dataset.themeMode = mode;
  } catch (e) {
    document.documentElement.dataset.theme = "dark";
    document.documentElement.dataset.themeMode = "auto";
  }
})();
