(function () {
  "use strict";

  var state = { result: null, cluster: null };

  function $(id) { return document.getElementById(id); }

  function esc(value) {
    if (value === null || value === undefined) { return ""; }
    return String(value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function postJson(url, body) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (r) { return r.json(); });
  }

  function getJson(url) {
    return fetch(url).then(function (r) { return r.json(); });
  }

  // ---------------------------------------------------------------- bootstrap

  function init() {
    getJson("/api/profiles").then(function (d) {
      var sel = $("profile");
      d.profiles.forEach(function (p) {
        var opt = document.createElement("option");
        opt.value = p.id;
        opt.textContent = p.label;
        sel.appendChild(opt);
      });
      sel.value = "general";
    });

    getJson("/api/samples").then(function (d) {
      var sel = $("sample");
      var blank = document.createElement("option");
      blank.value = "";
      blank.textContent = "load a sample...";
      sel.appendChild(blank);
      d.samples.forEach(function (s) {
        var opt = document.createElement("option");
        opt.value = s.id;
        opt.textContent = s.title;
        sel.appendChild(opt);
      });
    });

    $("analyze").addEventListener("click", analyze);
    $("cluster-btn").addEventListener("click", runCluster);
    $("clear").addEventListener("click", function () {
      $("input").value = "";
      $("result").hidden = true;
      $("empty").hidden = false;
    });
    $("sample-load").addEventListener("click", loadSample);
    $("export-md").addEventListener("click", function () { exportAs("markdown"); });
    $("export-json").addEventListener("click", function () { exportAs("json"); });
    $("export-csv").addEventListener("click", function () { exportAs("csv"); });
    $("save-run").addEventListener("click", saveRun);

    var tabs = document.querySelectorAll(".tab");
    Array.prototype.forEach.call(tabs, function (btn) {
      btn.addEventListener("click", function () {
        Array.prototype.forEach.call(tabs, function (b) { b.classList.remove("active"); });
        var panels = document.querySelectorAll(".tabpanel");
        Array.prototype.forEach.call(panels, function (p) { p.classList.remove("active"); });
        btn.classList.add("active");
        var panel = document.getElementById("tab-" + btn.getAttribute("data-tab"));
        if (panel) { panel.classList.add("active"); }
      });
    });

    loadRuns();
  }

  function loadSample() {
    var id = $("sample").value;
    if (!id) { return; }
    getJson("/api/samples/" + encodeURIComponent(id)).then(function (d) {
      $("input").value = d.text || "";
      analyze();
    });
  }

  // ---------------------------------------------------------------- analysis

  function analyze() {
    var text = $("input").value;
    var profile = $("profile").value || "general";
    var language = $("language").value || "auto";
    $("analyze").disabled = true;
    postJson("/api/analyze", { text: text, profile: profile, language: language })
      .then(function (data) {
        state.result = data;
        render(data);
      })
      .finally(function () { $("analyze").disabled = false; });
  }

  function runCluster() {
    var text = $("input").value;
    postJson("/api/cluster", { text: text }).then(function (data) {
      state.cluster = data;
      renderCluster(data);
      var tab = document.querySelector('.tab[data-tab="cluster"]');
      if (tab) { tab.click(); }
    });
  }

  // ---------------------------------------------------------------- rendering

  function render(data) {
    $("empty").hidden = true;
    $("result").hidden = false;
    renderVerdict(data);
    renderAxes(data);
    renderFailure(data);
    renderHypotheses(data);
    renderFindings(data);
    renderTriage(data);
    renderRepro(data);
    renderPlan(data);
    renderLogs(data);
    if (state.cluster) { renderCluster(state.cluster); }
  }

  function renderVerdict(data) {
    var sc = data.scorecard || {};
    $("score").textContent = sc.overall;
    $("verdict").textContent = sc.verdict;
    $("verdict-blurb").textContent = sc.verdict_blurb || "";
    var meta = data.meta || {};
    var cls = data.classification || {};
    $("meta-line").textContent =
      meta.language + " | " + meta.occurrence_count + " occurrence(s) | " +
      cls.label + " (" + cls.severity + ", confidence " + cls.confidence + "%) | profile: " +
      (sc.profile_label || sc.profile);
    var caps = sc.caps || [];
    $("caps").innerHTML = caps.map(function (c) {
      return '<div class="cap">' + esc(c.reason) + "</div>";
    }).join("");
  }

  function renderAxes(data) {
    var axes = (data.scorecard || {}).axes || [];
    $("axes").innerHTML = axes.map(function (a) {
      var pct = Math.max(2, Math.min(100, a.score));
      return '<div class="axis-row">' +
        '<div class="axis-name">' + esc(a.label) + "<small>" + esc(a.desc) + "</small></div>" +
        '<div class="bar"><span style="width:' + pct + '%"></span></div>' +
        '<div class="axis-score">' + esc(a.score) + "</div>" +
        "</div>";
    }).join("");
  }

  function renderFailure(data) {
    var p = data.primary;
    if (!p) {
      $("failure").innerHTML = '<p class="muted">No failure was parsed from this paste.</p>';
      return;
    }
    var origin = p.origin_frame;
    var html = '<dl class="kv">' +
      "<dt>Type</dt><dd><code>" + esc(p.error_type || "none") + "</code></dd>" +
      "<dt>Message</dt><dd>" + esc(p.message || "none") + "</dd>" +
      "<dt>Language</dt><dd>" + esc(p.language) + "</dd>" +
      "<dt>Chain depth</dt><dd>" + esc(p.chain_length) + "</dd>" +
      "<dt>Origin frame</dt><dd>" + (origin ? "<code>" + esc(origin.location) + "</code> " +
        esc(origin.function) + " <span class='muted small'>(" + esc(origin.origin) + ")</span>" : "none") + "</dd>" +
      "</dl>";
    if (p.frames && p.frames.length) {
      html += "<h3 style='margin-top:14px'>Frames</h3><table><thead><tr><th>#</th><th>Function</th>" +
        "<th>Location</th><th>Origin</th></tr></thead><tbody>" +
        p.frames.map(function (f) {
          return "<tr><td>" + esc(f.index) + "</td><td>" + esc(f.function) + "</td><td><code>" +
            esc(f.location) + "</code></td><td>" + esc(f.origin) + "</td></tr>";
        }).join("") + "</tbody></table>";
    }
    $("failure").innerHTML = html;
  }

  function renderHypotheses(data) {
    var hyps = data.hypotheses || [];
    if (!hyps.length) {
      $("tab-hypotheses").innerHTML = '<p class="muted">No hypotheses could be built.</p>';
      return;
    }
    $("tab-hypotheses").innerHTML = hyps.map(function (h) {
      return '<div class="hyp"><h4>' + esc(h.rank) + '. ' + esc(h.cause) +
        ' <span class="chip ' + (h.likelihood === "high" ? "ok" : "low") + '">' + esc(h.likelihood) + "</span></h4>" +
        "<p><strong>Why:</strong> " + esc(h.why) + "</p>" +
        "<p><strong>Check:</strong> " + esc(h.check) + "</p></div>";
    }).join("");
  }

  function renderFindings(data) {
    var findings = data.findings || [];
    if (!findings.length) {
      $("tab-findings").innerHTML = '<p class="muted">No findings. This paste is in good shape.</p>';
      return;
    }
    $("tab-findings").innerHTML = findings.map(function (f) {
      return '<div class="finding ' + esc(f.severity) + '"><h4>' +
        '<span class="chip ' + esc(f.severity) + '">' + esc(f.severity) + "</span>" + esc(f.title) + "</h4>" +
        '<p class="evidence">' + esc(f.evidence) + "</p>" +
        "<p><strong>Why it matters:</strong> " + esc(f.why_it_matters) + "</p>" +
        "<p><strong>Fix:</strong> " + esc(f.fix) + "</p></div>";
    }).join("");
  }

  function renderTriage(data) {
    var steps = data.triage || [];
    $("tab-triage").innerHTML = steps.map(function (s) {
      return '<div class="step"><div class="step-n">' + esc(s.step) + '</div>' +
        '<div class="step-time">' + esc(s.timebox) + "</div>" +
        '<div><strong>' + esc(s.action) + "</strong><p class='muted'>" + esc(s.detail) + "</p></div></div>";
    }).join("") || '<p class="muted">No checklist.</p>';
  }

  function renderRepro(data) {
    var repro = data.repro || {};
    var mq = data.message_quality || {};
    var html = "";
    if (mq.score !== undefined) {
      html += "<p><span class='chip ok'>message quality " + esc(mq.score) + "/100</span></p>";
      if (mq.issues && mq.issues.length) {
        html += "<ul>" + mq.issues.map(function (i) { return "<li>" + esc(i) + "</li>"; }).join("") + "</ul>";
      }
      if (mq.suggested_message) {
        html += "<p class='muted'>Suggested message</p><pre>" + esc(mq.suggested_message) + "</pre>";
      }
    }
    if (repro.skeleton) {
      html += "<p class='muted'>Minimal reproduction (" + esc(repro.language) + ")</p><pre>" +
        esc(repro.skeleton) + "</pre>";
    }
    $("tab-repro").innerHTML = html || '<p class="muted">Nothing to show.</p>';
  }

  function renderPlan(data) {
    var plan = data.fix_plan || [];
    $("tab-plan").innerHTML = plan.map(function (p) {
      var gain = p.gain ? " <span class='chip ok'>+" + esc(p.gain) + " pts</span>" : "";
      var eff = p.effort ? " <span class='chip low'>" + esc(p.effort) + "</span>" : "";
      return '<div class="hyp"><h4>' + esc(p.rank) + '. ' + esc(p.title) + gain + eff + "</h4>" +
        "<p>" + esc(p.detail) + "</p></div>";
    }).join("") || '<p class="muted">No fix plan.</p>';
  }

  function renderLogs(data) {
    var logs = data.logs || {};
    var rows = Object.keys(logs.levels || {}).map(function (k) {
      return "<tr><td>" + esc(k) + "</td><td>" + esc(logs.levels[k]) + "</td></tr>";
    }).join("");
    var html = "<dl class='kv'>" +
      "<dt>Log lines</dt><dd>" + esc(logs.line_count) + "</dd>" +
      "<dt>Error lines</dt><dd>" + esc(logs.error_lines) + "</dd>" +
      "<dt>Warn lines</dt><dd>" + esc(logs.warn_lines) + "</dd>" +
      "<dt>Timestamps</dt><dd>" + (logs.has_timestamps ? "yes" : "no") + "</dd>" +
      "<dt>Correlation id</dt><dd>" + (logs.has_correlation_id ? "yes" : "no") + "</dd>" +
      "<dt>Distinct messages</dt><dd>" + esc(logs.distinct_messages) + "</dd>" +
      "<dt>Loggers</dt><dd>" + esc((logs.loggers || []).join(", ") || "none") + "</dd>" +
      "</dl>";
    if (rows) {
      html += "<h3 style='margin-top:12px'>Levels</h3><table><thead><tr><th>Level</th><th>Count</th></tr></thead><tbody>" + rows + "</tbody></table>";
    }
    if (logs.repeated_messages && logs.repeated_messages.length) {
      html += "<h3 style='margin-top:12px'>Repeated</h3><table><thead><tr><th>Message</th><th>Count</th></tr></thead><tbody>" +
        logs.repeated_messages.map(function (m) {
          return "<tr><td>" + esc(m.message) + "</td><td>" + esc(m.count) + "</td></tr>";
        }).join("") + "</tbody></table>";
    }
    $("tab-logs").innerHTML = html;
  }

  function renderCluster(data) {
    if (!data) { return; }
    var html = "<p class='muted'>" + esc(data.total_occurrences) + " occurrences, " +
      esc(data.distinct_signatures) + " distinct signatures.</p>";
    (data.insights || []).forEach(function (i) {
      html += '<div class="finding medium"><p>' + esc(i.text) + "</p></div>";
    });
    var clusters = data.clusters || [];
    if (clusters.length) {
      html += "<table><thead><tr><th>Count</th><th>Share</th><th>Signature</th><th>Class</th></tr></thead><tbody>" +
        clusters.map(function (c) {
          return "<tr><td>" + esc(c.count) + "</td><td>" + esc(c.share) + "%</td><td>" +
            esc(c.label) + "</td><td>" + esc(c.category_label) + "</td></tr>";
        }).join("") + "</tbody></table>";
    }
    if ((data.chokepoints || []).length) {
      html += "<h3 style='margin-top:12px'>Chokepoints</h3><ul>" +
        data.chokepoints.map(function (c) {
          return "<li><code>" + esc(c.location) + "</code> - " + esc(c.distinct_errors) + " distinct errors</li>";
        }).join("") + "</ul>";
    }
    $("tab-cluster").innerHTML = html;
  }

  // ---------------------------------------------------------------- exports

  function exportAs(format) {
    var body = { text: $("input").value, profile: $("profile").value || "general", format: format };
    fetch("/api/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (r) { return r.blob(); }).then(function (blob) {
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url;
      a.download = "stacktrace-report." + (format === "markdown" ? "md" : format);
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  }

  // ---------------------------------------------------------------- run log

  function saveRun() {
    if (!state.result) { return; }
    postJson("/api/runs", {
      result: state.result,
      paste: $("input").value,
      self_rating: $("rating").value ? parseInt($("rating").value, 10) : null,
      notes: $("notes").value
    }).then(function () { loadRuns(); });
  }

  function loadRuns() {
    getJson("/api/runs?limit=20").then(function (d) {
      var runs = d.runs || [];
      $("runs").innerHTML = runs.map(function (r) {
        return '<div class="run"><span class="run-score">' + esc(r.score) + "</span>" +
          "<span class='grow'>" + esc(r.category) + " - " + esc(r.verdict) +
          (r.self_rating ? " - rated " + esc(r.self_rating) + "/5" : "") +
          (r.notes ? " - " + esc(r.notes) : "") + "</span>" +
          '<span class="muted small">' + esc(r.created_at) + "</span>" +
          '<button class="tiny ghost" data-del="' + esc(r.id) + '">delete</button></div>';
      }).join("") || '<p class="muted">No saved runs yet.</p>';
      var buttons = document.querySelectorAll("button[data-del]");
      Array.prototype.forEach.call(buttons, function (btn) {
        btn.addEventListener("click", function () {
          fetch("/api/runs/" + btn.getAttribute("data-del"), { method: "DELETE" })
            .then(loadRuns);
        });
      });
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();
