(() => {
  "use strict";

  const FONT_STACK = '-apple-system, BlinkMacSystemFont, Inter, "Segoe UI", sans-serif';
  const CYTOSCAPE_FONT = FONT_STACK;

  function short(value, prefix = 10, suffix = 6) {
    const text = String(value || "");
    if (text.length <= prefix + suffix + 3) return text;
    return `${text.slice(0, prefix)}…${text.slice(-suffix)}`;
  }

  function fmtTime(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
  }

  function fmtClock(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleTimeString([], { hour12: false });
  }

  function fmtDuration(start, end) {
    const a = Date.parse(start || "");
    const b = Date.parse(end || start || "");
    if (Number.isNaN(a) || Number.isNaN(b) || b < a) return "—";
    const ms = b - a;
    if (ms < 1000) return `${ms} ms`;
    const seconds = ms / 1000;
    if (seconds < 60) return `${seconds.toFixed(1)} s`;
    return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  }

  function fmtCost(value) {
    const n = Number(value);
    return Number.isFinite(n) ? `$${n.toFixed(2)}` : "—";
  }

  function fmtBytes(value) {
    const size = Number(value || 0);
    if (size < 1024) return `${size} B`;
    if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`;
    return `${(size / 1024 / 1024).toFixed(1)} MiB`;
  }

  function targetHost(value) {
    const text = String(value || "").trim();
    if (!text) return "";
    const match = text.match(/https?:\/\/[^\s'"<>]+/);
    if (!match) return text;
    try {
      return new URL(match[0]).host || text;
    } catch (_) {
      return match[0];
    }
  }

  function statusClass(status) {
    return String(status || "unknown").toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
  }

  function nodeDisplay(node) {
    const data = node.data || {};
    const nodeId = String(node.id || "");
    if (node.type === "origin") {
      const target = data.target || node.label || "";
      return { label: targetHost(target) || node.label || node.id, subtitle: "stated input", title: target || node.id };
    }
    if (node.type === "goal") {
      return { label: data.objective || node.label || node.id, subtitle: "stated goal · not proof", title: data.objective || node.id };
    }
    if (node.type === "run") {
      const runId = data.run_id || nodeId.replace(/^run:/, "");
      return { label: short(runId, 8, 8), subtitle: data.mode || "", title: runId };
    }
    if (node.type === "call") {
      const callId = data.call_id || nodeId.replace(/^call:/, "");
      const parts = [fmtDuration(data.started_at, data.ended_at), data.num_turns != null ? `${data.num_turns} turns` : ""]
        .filter((part) => part && part !== "—");
      return { label: `call ${String(callId).slice(0, 8)}`, subtitle: parts.join(" · ") || "recorded call", title: callId };
    }
    if (node.type === "session") {
      const sessionId = data.session_id || nodeId.replace(/^session:/, "");
      return { label: short(sessionId, 8, 8), subtitle: "SDK session", title: sessionId };
    }
    if (node.type === "evidence") {
      const tools = (data.breakdown || []).map((item) => item.tool_name).filter(Boolean).slice(0, 2);
      return {
        label: `${data.count || 0} receipts`,
        subtitle: tools.join(" · ") || (data.tool_names || []).slice(0, 2).join(" · ") || "captured evidence",
        title: node.label || node.id,
      };
    }
    return { label: node.label || node.id, subtitle: node.subtitle || "", title: node.label || node.id };
  }

  function scopedGraph(graph, runId) {
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];
    const runNodeId = `run:${runId}`;
    const selectedRun = nodes.find((node) => node.id === runNodeId);
    if (!selectedRun) return { nodes: [], edges: [] };
    const keep = new Set([runNodeId]);
    for (const node of nodes) {
      if ((node.type === "origin" || node.type === "goal") && (node.data?.run_ids || []).includes(runId)) keep.add(node.id);
      if ((node.type === "call" || node.type === "evidence") && node.data?.run_id === runId) keep.add(node.id);
      if (node.type === "run" && node.data?.parent_run_id === runId) keep.add(node.id);
    }
    if (selectedRun.data?.parent_run_id) keep.add(`run:${selectedRun.data.parent_run_id}`);
    for (const edge of edges) {
      if (keep.has(edge.source) && String(edge.target).startsWith("session:")) keep.add(edge.target);
    }
    const scopedNodes = nodes.filter((node) => keep.has(node.id));
    let scopedEdges = edges.filter((edge) => keep.has(edge.source) && keep.has(edge.target));
    const hasOriginLink = scopedEdges.some((edge) => edge.kind === "origin" && edge.target === runNodeId);
    if (!hasOriginLink) {
      const extras = scopedNodes
        .filter((node) => node.type === "origin")
        .map((node) => ({
          id: `origin-link:${node.id}->${runNodeId}`,
          source: node.id,
          target: runNodeId,
          kind: "origin",
          status: "",
          appears_at: "",
          data: {},
        }));
      scopedEdges = scopedEdges.concat(extras);
    }
    return { nodes: scopedNodes, edges: scopedEdges };
  }

  async function api(path) {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return response.json();
  }

  async function fetchText(path) {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return response.text();
  }

  const CY_STYLE = [
    {
      selector: "node",
      style: {
        shape: "round-rectangle",
        "background-color": "#94a3b8",
        label: "data(label)",
        color: "#fff",
        "font-family": CYTOSCAPE_FONT,
        "text-valign": "center",
        "text-halign": "center",
        "font-size": "11px",
        "font-weight": "bold",
        "text-wrap": "wrap",
        "text-max-width": "130px",
        "text-overflow-wrap": "anywhere",
        width: 150,
        height: 40,
        "border-width": 0,
      },
    },
    { selector: 'node[nodeType="origin"]', style: { "background-color": "#14b8a6" } },
    { selector: 'node[nodeType="goal"]', style: { "background-color": "#f43f5e" } },
    { selector: 'node[nodeType="run"]', style: { "background-color": "#c7d2fe", color: "#3730a3" } },
    { selector: 'node[nodeType="run"][?viewed]', style: { "background-color": "#6366f1", color: "#fff" } },
    { selector: 'node[nodeType="call"]', style: { "background-color": "#818cf8" } },
    { selector: 'node[nodeType="session"]', style: { "background-color": "#a78bfa" } },
    {
      selector: 'node[nodeType="evidence"]',
      style: {
        "background-color": "#f1f5f9",
        color: "#475569",
        "border-width": 1.5,
        "border-color": "#cbd5e1",
        "border-style": "dashed",
      },
    },
    { selector: "node[?failed]", style: { "border-width": 2, "border-color": "#f43f5e" } },
    {
      selector: "edge",
      style: {
        width: 1.5,
        "line-color": "#cbd5e1",
        "target-arrow-color": "#cbd5e1",
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
        "arrow-scale": 0.8,
      },
    },
    { selector: 'edge[kind="outcome"]', style: { width: 2, "line-color": "#6ee7b7", "target-arrow-color": "#6ee7b7" } },
    {
      selector: 'edge[kind="session"], edge[kind="evidence"], edge[kind="session_lineage"]',
      style: { "line-style": "dashed" },
    },
    {
      selector: "node.sel",
      style: { "underlay-color": "#93c5fd", "underlay-opacity": 0.28, "underlay-padding": 8, "z-index": 1001 },
    },
    {
      selector: "edge.sel",
      style: { "overlay-color": "#93c5fd", "overlay-opacity": 0.22, "overlay-padding": 5, "z-index": 1000 },
    },
    {
      selector: "node.focus",
      style: { "border-width": 3, "border-color": "#312e81", "border-opacity": 0.95, "z-index": 1000 },
    },
    { selector: ".faded", style: { opacity: 0.35 } },
  ];

  cytoscape.use(cytoscapeDagre);

  let cy = null;
  let pollTimer = null;

  Vue.createApp({
    data() {
      return {
        view: "list",
        routeRunId: "",
        overview: null,
        runs: [],
        latestRunId: "",
        graph: { nodes: [], edges: [], events: [] },
        detail: null,
        selectedNodeId: "",
        selectedEdgeId: "",
        sideTab: "detail",
        layoutMode: "dagre_tb",
        replay: { active: false, playing: false, index: -1, timer: null, stepMs: 1100 },
        snapshot: { visible: false, format: "timeline", text: "", copied: false },
        error: "",
      };
    },
    computed: {
      runRow() {
        return this.runs.find((run) => run.run_id === this.routeRunId) || null;
      },
      runData() {
        return (this.detail && this.detail.run) || this.runRow || {};
      },
      runStatus() {
        return this.runData.status || "unknown";
      },
      runHost() {
        return targetHost(this.runData.target) || "no target";
      },
      runCost() {
        const record = (this.detail && this.detail.record) || {};
        if (typeof record.total_cost_usd === "number") return record.total_cost_usd;
        const calls = (this.detail && this.detail.calls) || [];
        if (calls.length) return calls.reduce((sum, call) => sum + (Number(call.cost_usd) || 0), 0);
        return Number(this.runData.total_cost_usd) || 0;
      },
      runTurns() {
        const record = (this.detail && this.detail.record) || {};
        if (typeof record.num_turns === "number") return record.num_turns;
        const calls = (this.detail && this.detail.calls) || [];
        if (calls.length) return calls.reduce((sum, call) => sum + (Number(call.num_turns) || 0), 0);
        return this.runData.total_num_turns ?? "—";
      },
      runDuration() {
        return fmtDuration(this.runData.created_at, this.runData.updated_at);
      },
      headerMeta() {
        const calls = (this.detail && this.detail.calls) || [];
        const artifacts = (this.detail && this.detail.artifacts) || [];
        return `${calls.length} calls · ${artifacts.length} evidence · ${fmtCost(this.runCost)}`;
      },
      reportText() {
        const record = (this.detail && this.detail.record) || {};
        const text = record.assistant_text || record.result || "";
        return typeof text === "string" ? text : JSON.stringify(text, null, 2);
      },
      followUps() {
        return (this.detail && this.detail.interventions) || [];
      },
      runEvents() {
        return (this.graph.events || []).filter((event) => event.run_id === this.routeRunId);
      },
      selectedNode() {
        return this.selectedNodeId ? this.nodeById(this.selectedNodeId) : null;
      },
      selectedEdge() {
        return this.selectedEdgeId ? this.edgeById(this.selectedEdgeId) : null;
      },
      selectedId() {
        return this.selectedNodeId || this.selectedEdgeId || "";
      },
      selectedType() {
        if (this.selectedNode) return this.selectedNode.type;
        if (this.selectedEdge) return "edge";
        return "";
      },
      selectedLabel() {
        if (this.selectedEdge) return this.selectedEdge.label || this.selectedEdge.kind || this.selectedEdge.id;
        if (this.selectedNode) return this.selectedNode.label || this.selectedNode.id;
        return "";
      },
      selectedFields() {
        if (this.selectedEdge) return this.edgeFields(this.selectedEdge);
        if (!this.selectedNode) return [];
        return this.nodeFields(this.selectedNode);
      },
      chipColor() {
        const map = {
          origin: { bg: "#14b8a6", fg: "#fff" },
          goal: { bg: "#f43f5e", fg: "#fff" },
          run: { bg: "#6366f1", fg: "#fff" },
          call: { bg: "#818cf8", fg: "#fff" },
          session: { bg: "#a78bfa", fg: "#fff" },
          evidence: { bg: "#e2e8f0", fg: "#475569" },
          edge: { bg: "#cbd5e1", fg: "#334155" },
        };
        return map[this.selectedType] || map.edge;
      },
      evidenceRows() {
        const rows = (this.detail && this.detail.artifacts) || [];
        const node = this.selectedNode;
        if (node && node.type === "evidence") {
          const callId = String(node.data?.call_id || "");
          return rows.filter((row) => String(row.call_id || "") === callId);
        }
        return rows;
      },
      totalCost() {
        if (this.overview && typeof this.overview.total_cost_usd === "number") return this.overview.total_cost_usd;
        return this.runs.reduce((sum, run) => sum + (Number(run.total_cost_usd) || 0), 0);
      },
    },
    methods: {
      short,
      fmtTime,
      fmtClock,
      fmtDuration,
      fmtCost,
      fmtBytes,
      statusClass,
      statusCount(status) {
        return this.runs.filter((run) => String(run.status || "") === status).length;
      },
      cardTitle(run) {
        return targetHost(run.target) || "no target";
      },
      cardMeta(run) {
        return [
          `${run.total_num_turns || 0} turns`,
          `${run.artifact_count || 0} evidence`,
          fmtDuration(run.created_at, run.updated_at),
          fmtCost(run.total_cost_usd),
        ].filter((part) => part && part !== "—").join(" · ");
      },
      runField(key) {
        return this.runData[key] || "";
      },
      nodeById(id) {
        return (this.graph.nodes || []).find((node) => node.id === id) || null;
      },
      edgeById(id) {
        return (this.graph.edges || []).find((edge) => edge.id === id) || null;
      },
      nodeFields(node) {
        const data = node.data || {};
        if (node.type === "origin" || node.type === "goal") {
          return [
            ["Target", data.target || "—"],
            ["Objective", data.objective || "—"],
            ["Runs", String((data.run_ids || []).length)],
            ["Boundary", node.type === "goal" ? "stated / reported, not proof" : "stated input"],
          ];
        }
        if (node.type === "run") {
          return [
            ["Status", node.status || data.status || "—"],
            ["Mode", data.mode || "—"],
            ["Objective", data.objective || "—"],
            ["Created", fmtTime(data.created_at)],
            ["Updated", fmtTime(data.updated_at)],
            ["Parent run", data.parent_run_id ? short(data.parent_run_id, 18, 8) : "—", "mono"],
            ["Session", short(data.primary_session_id, 16, 10), "mono"],
          ];
        }
        if (node.type === "call") {
          return [
            ["Status", data.result_status || "—"],
            ["Run", short(data.run_id, 18, 8), "mono"],
            ["Session", short(data.session_id, 16, 10), "mono"],
            ["Started", fmtTime(data.started_at)],
            ["Ended", fmtTime(data.ended_at)],
            ["Turns", data.num_turns ?? "—"],
            ["Cost", typeof data.cost_usd === "number" ? `$${data.cost_usd.toFixed(4)}` : "—"],
            ["Terminal", data.terminal_reason || data.error_class || "—"],
          ];
        }
        if (node.type === "session") {
          return [
            ["Status", data.status || "—"],
            ["Origin run", short(data.origin_run_id, 18, 8), "mono"],
            ["Parent session", data.parent_session_id ? short(data.parent_session_id, 16, 10) : "—", "mono"],
            ["Created", fmtTime(data.created_at)],
            ["Last used", fmtTime(data.last_used_at)],
            ["Fork reason", data.fork_reason || "—"],
          ];
        }
        if (node.type === "evidence") {
          return [
            ["Run", short(data.run_id, 18, 8), "mono"],
            ["Call", data.call_id ? short(data.call_id, 12, 8) : "run-scoped", "mono"],
            ["Source kinds", (data.source_kinds || []).join(", ") || "—"],
            ["Tools", (data.tool_names || []).join(", ") || "—"],
            ["Receipts", String(data.count || 0)],
            ["Total size", fmtBytes(data.total_size)],
          ];
        }
        return [["Status", node.status || "—"]];
      },
      edgeFields(edge) {
        const data = edge.data || {};
        const runId = data.run_id || data.result_run_id || "";
        return [
          ["Kind", edge.kind || "—"],
          ["Source", edge.source, "mono"],
          ["Target", edge.target, "mono"],
          ["Appears", fmtTime(edge.appears_at)],
          ["Status", edge.status || "—"],
          ["Run", runId ? short(runId, 18, 8) : "—", "mono"],
        ];
      },
      openRun(runId) {
        location.hash = `#/run/${encodeURIComponent(runId)}`;
      },
      goList() {
        location.hash = "#/";
      },
      onRoute() {
        const match = (location.hash || "#/").match(/^#\/run\/(.+)$/);
        if (match) {
          const runId = decodeURIComponent(match[1]);
          if (this.view !== "run" || this.routeRunId !== runId) this.enterRun(runId);
          return;
        }
        if (this.view !== "list") this.enterList();
        else this.refresh();
      },
      enterList() {
        this.exitReplay();
        this.destroyCy();
        this.view = "list";
        this.routeRunId = "";
        this.selectedNodeId = "";
        this.selectedEdgeId = "";
        this.detail = null;
        this.refresh();
      },
      enterRun(runId) {
        this.exitReplay();
        this.view = "run";
        this.routeRunId = runId;
        this.selectedNodeId = "";
        this.selectedEdgeId = "";
        this.sideTab = "detail";
        this.detail = null;
        this.refresh();
      },
      async refresh() {
        if (this.replay.active) return;
        try {
          if (this.view === "list") {
            const [overview, runs] = await Promise.all([api("/api/overview"), api("/api/runs")]);
            this.overview = overview;
            this.runs = runs.runs || [];
            this.latestRunId = runs.latest_run_id || "";
          } else {
            const [runs, graph, detail] = await Promise.all([
              api("/api/runs"),
              api("/api/graph"),
              api(`/api/runs/${encodeURIComponent(this.routeRunId)}`),
            ]);
            this.runs = runs.runs || [];
            this.graph = graph;
            this.detail = detail;
            this.$nextTick(() => {
              if (this.view !== "run") return;
              if (!cy) this.buildCy();
              else this.updateCy();
            });
          }
          this.error = "";
        } catch (err) {
          this.error = `Refresh failed: ${err.message}`;
        }
      },
      graphElements() {
        const scoped = scopedGraph(this.graph, this.routeRunId);
        const nodes = scoped.nodes.map((node) => ({
          data: {
            id: node.id,
            label: nodeDisplay(node).label,
            nodeType: node.type,
            viewed: node.id === `run:${this.routeRunId}`,
            failed: ["failed", "error"].includes(String(node.status || "").toLowerCase()),
            appears: node.appears_at || "",
          },
        }));
        const edges = scoped.edges.map((edge) => ({
          data: {
            id: edge.id,
            source: edge.source,
            target: edge.target,
            kind: edge.kind || "",
            appears: edge.appears_at || "",
          },
        }));
        return [...nodes, ...edges];
      },
      layoutOptions() {
        return {
          name: "dagre",
          rankDir: this.layoutMode === "dagre_lr" ? "LR" : "TB",
          nodeSep: 30,
          rankSep: 50,
          animate: false,
        };
      },
      buildCy() {
        const container = this.$refs.cyEl;
        if (!container) return;
        this.destroyCy();
        cy = cytoscape({
          container,
          elements: this.graphElements(),
          style: CY_STYLE,
          minZoom: 0.2,
          maxZoom: 1.4,
          wheelSensitivity: 0.3,
          layout: this.layoutOptions(),
        });
        cy.on("tap", "node", (event) => this.pickElement(event.target));
        cy.on("tap", "edge", (event) => this.pickElement(event.target));
        cy.on("tap", (event) => {
          if (event.target === cy) this.clearSelection();
        });
        cy.ready(() => {
          cy.fit(undefined, 40);
        });
      },
      destroyCy() {
        if (cy) {
          cy.destroy();
          cy = null;
        }
      },
      updateCy() {
        if (!cy) return;
        const elements = this.graphElements();
        const nextIds = new Set(elements.map((item) => item.data.id));
        const currentIds = new Set(cy.elements().map((element) => element.id()));
        const same = nextIds.size === currentIds.size && [...nextIds].every((id) => currentIds.has(id));
        if (same) {
          cy.batch(() => {
            for (const item of elements) {
              const target = cy.getElementById(item.data.id);
              if (target.nonempty()) target.data(item.data);
            }
          });
        } else {
          cy.elements().remove();
          cy.add(elements);
          cy.layout(this.layoutOptions()).run();
        }
        if (this.replay.active) this.applyReplayVisibility();
        else this.applySelection();
      },
      relayout() {
        if (!cy) return;
        cy.layout(this.layoutOptions()).run();
        this.$nextTick(() => this.fitGraph());
      },
      fitGraph() {
        if (cy) cy.fit(undefined, 40);
      },
      pickElement(target) {
        if (target.isNode()) {
          this.selectedNodeId = target.id();
          this.selectedEdgeId = "";
        } else {
          this.selectedEdgeId = target.id();
          this.selectedNodeId = "";
        }
        this.applySelection();
      },
      applySelection() {
        if (!cy) return;
        cy.batch(() => {
          cy.elements().removeClass("sel faded");
          const id = this.selectedNodeId || this.selectedEdgeId;
          if (!id) return;
          const element = cy.getElementById(id);
          if (element.empty()) return;
          const hood = element.closedNeighborhood();
          cy.elements().difference(hood).addClass("faded");
          element.addClass("sel");
        });
      },
      clearSelection() {
        this.selectedNodeId = "";
        this.selectedEdgeId = "";
        this.applySelection();
      },
      focusEvent(event) {
        if (!event || !event.target_id) return;
        const element = cy && cy.getElementById(event.target_id);
        if (element && element.nonempty()) {
          this.pickElement(element);
          if (event.target_type !== "edge") cy.center(element);
        }
      },
      eventCutoff() {
        if (!this.replay.active || this.replay.index < 0) return Infinity;
        const event = this.runEvents[Math.min(this.replay.index, this.runEvents.length - 1)];
        const parsed = Date.parse((event && event.timestamp) || "");
        return Number.isNaN(parsed) ? Infinity : parsed;
      },
      applyReplayVisibility() {
        if (!cy) return;
        const cutoff = this.eventCutoff();
        cy.batch(() => {
          cy.elements().forEach((element) => {
            const at = Date.parse(element.data("appears") || "");
            const show = !this.replay.active || Number.isNaN(at) || at <= cutoff;
            element.style("display", show ? "element" : "none");
          });
        });
      },
      applyReplayFrame(index) {
        const events = this.runEvents;
        this.replay.index = Math.max(-1, Math.min(index, events.length - 1));
        this.applyReplayVisibility();
        if (!cy) return;
        const event = events[this.replay.index];
        cy.batch(() => {
          cy.elements().removeClass("focus");
          if (event && event.target_id) {
            const target = cy.getElementById(event.target_id);
            if (target.nonempty()) {
              target.addClass("focus");
              if (event.target_type !== "edge") cy.center(target);
            }
          }
        });
      },
      stopReplayTimer() {
        if (this.replay.timer) clearTimeout(this.replay.timer);
        this.replay.timer = null;
      },
      scheduleReplay() {
        this.stopReplayTimer();
        if (!this.replay.active || !this.replay.playing) return;
        if (this.replay.index >= this.runEvents.length - 1) {
          this.replay.playing = false;
          return;
        }
        this.replay.timer = setTimeout(() => {
          this.applyReplayFrame(this.replay.index + 1);
          this.scheduleReplay();
        }, this.replay.stepMs);
      },
      startReplay() {
        if (!this.runEvents.length) return;
        this.replay.active = true;
        this.replay.playing = true;
        this.sideTab = "log";
        this.applyReplayFrame(0);
        this.scheduleReplay();
      },
      toggleReplay() {
        this.replay.playing = !this.replay.playing;
        this.scheduleReplay();
      },
      restartReplay() {
        this.replay.playing = true;
        this.applyReplayFrame(0);
        this.scheduleReplay();
      },
      exitReplay() {
        this.stopReplayTimer();
        this.replay.active = false;
        this.replay.playing = false;
        this.replay.index = -1;
        if (cy) {
          cy.batch(() => {
            cy.elements().removeClass("focus");
            cy.elements().style("display", "element");
          });
        }
      },
      async openSnapshot() {
        this.snapshot.visible = true;
        this.snapshot.copied = false;
        await this.loadSnapshot();
      },
      async loadSnapshot() {
        this.snapshot.text = "Loading…";
        try {
          if (this.snapshot.format === "json") {
            this.snapshot.text = JSON.stringify(await api("/api/export?format=json"), null, 2);
          } else {
            this.snapshot.text = await fetchText("/api/export?format=timeline");
          }
        } catch (err) {
          this.snapshot.text = `Snapshot failed: ${err.message}`;
        }
      },
      async copySnapshot() {
        try {
          await navigator.clipboard.writeText(this.snapshot.text || "");
          this.snapshot.copied = true;
          setTimeout(() => { this.snapshot.copied = false; }, 1000);
        } catch (_) {
          this.snapshot.copied = false;
        }
      },
    },
    mounted() {
      window.addEventListener("hashchange", this.onRoute);
      this.onRoute();
      pollTimer = setInterval(() => this.refresh(), 5000);
    },
    beforeUnmount() {
      if (pollTimer) clearInterval(pollTimer);
      window.removeEventListener("hashchange", this.onRoute);
      this.exitReplay();
      this.destroyCy();
    },
  }).mount("#app");
})();
