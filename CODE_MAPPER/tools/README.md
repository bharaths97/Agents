# CODE_MAPPER Tools

Standalone utilities for analyzing CODE_MAPPER reports and results. These tools are independent of the report generation process and can be used with any JSON report file.

## Call Graph Viewer

**File:** `call_graph_viewer.html`

Standalone interactive visualization of cross-file function calls and dependencies. Load any `code_mapper_report_*.json` file to explore call graphs with pan/zoom, filtering, and layout options. Works 100% offline in your browser.

**When to use:** Use this tool to interactively explore and analyze call graphs separately from the main HTML report. Useful for detailed investigation, presentation, or sharing specific call chain analyses.

**Usage:**
```bash
# Open in browser
open call_graph_viewer.html

# Or copy to convenient location for quick access
cp call_graph_viewer.html ~/call_graph_viewer.html
open ~/call_graph_viewer.html
```

Then drag-and-drop or select a `code_mapper_report_*.json` file. Features include:
- Interactive node selection (highlights incoming/outgoing call paths)
- Filter by edge type (cross-file vs same-file calls)
- Multiple layout algorithms (hierarchical, grid, circle)
- Export visualization to PNG
- Real-time graph statistics (functions, edges, cross-file calls)
