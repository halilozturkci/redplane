/* Redplane static viewer. Runs under a hash-locked CSP: no eval, no inline
   handlers, no network. Data comes from the inert JSON block; the DOM is only
   shown/hidden, never built from finding text. */
(function () {
  "use strict";

  function readData() {
    var node = document.getElementById("redplane-data");
    if (!node) { return null; }
    try { return JSON.parse(node.textContent); } catch (err) { return null; }
  }

  var data = readData();
  if (!data) { return; }

  var FACETS = ["severity", "engine", "category", "sub_category", "target", "success", "waived", "kind"];
  var byId = {};
  data.findings.forEach(function (row) { byId[row.id] = row; });

  function facetValue(name) {
    var el = document.getElementById("facet-" + name);
    return el ? el.value : "";
  }

  function matches(row, query) {
    for (var i = 0; i < FACETS.length; i += 1) {
      var wanted = facetValue(FACETS[i]);
      if (wanted && row[FACETS[i]] !== wanted) { return false; }
    }
    if (query) {
      var haystack = (row.id + " " + row.category + " " + row.sub_category + " " + row.engine + " " + row.target).toLowerCase();
      var node = document.querySelector('details.finding[data-finding-id="' + cssEscape(row.id) + '"]');
      if (node) { haystack += " " + node.textContent.toLowerCase(); }
      if (haystack.indexOf(query) === -1) { return false; }
    }
    return true;
  }

  function cssEscape(value) {
    if (window.CSS && window.CSS.escape) { return window.CSS.escape(value); }
    return String(value).replace(/["\\]/g, "\\$&");
  }

  function applyFilters() {
    var queryEl = document.getElementById("facet-q");
    var query = queryEl ? queryEl.value.trim().toLowerCase() : "";
    var shown = 0;
    var nodes = document.querySelectorAll("details.finding");
    for (var i = 0; i < nodes.length; i += 1) {
      var node = nodes[i];
      var row = byId[node.getAttribute("data-finding-id")];
      var visible = row ? matches(row, query) : true;
      node.hidden = !visible;
      if (visible) { shown += 1; }
    }
    var count = document.getElementById("finding-count");
    if (count) { count.textContent = shown + " of " + nodes.length + " findings"; }
  }

  function resetFilters() {
    FACETS.forEach(function (name) {
      var el = document.getElementById("facet-" + name);
      if (el) { el.value = ""; }
    });
    var q = document.getElementById("facet-q");
    if (q) { q.value = ""; }
    applyFilters();
  }

  function setAllFindings(open) {
    var nodes = document.querySelectorAll("details.finding");
    for (var i = 0; i < nodes.length; i += 1) {
      if (!nodes[i].hidden) { nodes[i].open = open; }
    }
  }

  function showGate(threshold) {
    var panels = document.querySelectorAll(".gate-panel[data-threshold]");
    for (var i = 0; i < panels.length; i += 1) {
      panels[i].hidden = panels[i].getAttribute("data-threshold") !== threshold;
    }
  }

  function wire() {
    FACETS.forEach(function (name) {
      var el = document.getElementById("facet-" + name);
      if (el) { el.addEventListener("change", applyFilters); }
    });
    var q = document.getElementById("facet-q");
    if (q) { q.addEventListener("input", applyFilters); }
    var reset = document.getElementById("facet-reset");
    if (reset) { reset.addEventListener("click", resetFilters); }
    var expand = document.getElementById("findings-expand");
    if (expand) { expand.addEventListener("click", function () { setAllFindings(true); }); }
    var collapse = document.getElementById("findings-collapse");
    if (collapse) { collapse.addEventListener("click", function () { setAllFindings(false); }); }

    var gate = document.getElementById("gate-threshold");
    if (gate) {
      gate.addEventListener("change", function () { showGate(gate.value); });
      showGate(gate.value);
    }

    // Deep link: #finding=<id> opens that finding.
    var hash = window.location.hash;
    if (hash.indexOf("#finding=") === 0) {
    var wanted;
    try {
      wanted = decodeURIComponent(hash.slice("#finding=".length));
    } catch (err) {
      return; // malformed hash: ignore, keep the page interactive
    }
    var node = document.querySelector('details.finding[data-finding-id="' + cssEscape(wanted) + '"]');
      if (node) { node.open = true; node.scrollIntoView(); }
    }
    applyFilters();
    document.body.classList.add("js-ready");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();
