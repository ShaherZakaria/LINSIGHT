# -*- coding: utf-8 -*-
from __future__ import annotations




# ---------------------------------------------------------------------------
# The GUI: one self-contained page that carries the triage picture.
#
# --html writes a document - a flat page you read top to bottom and hand to
# someone. This is the other thing an analyst wants from the same data: a
# console to work the findings in, filter by severity, pivot on a technique,
# read the evidence beside the list rather than by scrolling to it.
#
# It stays one file with no dependency on the network, because the box that
# reads a triage collection is routinely the box that is not allowed to fetch
# anything. Tables are deliberately not bundled: --export already writes
# browser.html for those, and folding 3.3 million rows into this page would
# cost the instant first paint that makes it usable.

# Technique -> tactic, parent IDs only; a sub-technique inherits its parent's
# column. Only the tactic is stored: the technique's *name* already arrives in
# the finding's mitre string ("T1053.003 Scheduled Task: Cron"), so keeping a
# second copy here would be one more thing to hold consistent with ATT&CK.
# An ID that is not listed lands in "Other" rather than being dropped - a Sigma
# rule can carry any technique at all, and a hit that vanishes from the matrix
# because the map is short is worse than a hit in the wrong column.
ATTACK_TACTICS = {
    "T1592": "Reconnaissance", "T1595": "Reconnaissance",
    "T1587": "Resource Development", "T1588": "Resource Development",
    "T1608": "Resource Development",
    "T1133": "Initial Access", "T1190": "Initial Access",
    "T1195": "Initial Access", "T1566": "Initial Access",
    "T1059": "Execution", "T1203": "Execution", "T1204": "Execution",
    "T1569": "Execution", "T1610": "Execution",
    "T1053": "Persistence", "T1078": "Persistence", "T1098": "Persistence",
    "T1136": "Persistence", "T1176": "Persistence", "T1505": "Persistence",
    "T1525": "Persistence", "T1543": "Persistence", "T1546": "Persistence",
    "T1547": "Persistence", "T1554": "Persistence", "T1574": "Persistence",
    "T1068": "Privilege Escalation", "T1134": "Privilege Escalation",
    "T1548": "Privilege Escalation", "T1611": "Privilege Escalation",
    "T1014": "Defense Evasion", "T1027": "Defense Evasion",
    "T1036": "Defense Evasion", "T1055": "Defense Evasion",
    "T1070": "Defense Evasion", "T1140": "Defense Evasion",
    "T1205": "Defense Evasion", "T1218": "Defense Evasion",
    "T1222": "Defense Evasion", "T1480": "Defense Evasion",
    "T1497": "Defense Evasion", "T1553": "Defense Evasion",
    "T1562": "Defense Evasion", "T1564": "Defense Evasion",
    "T1620": "Defense Evasion",
    "T1003": "Credential Access", "T1040": "Credential Access",
    "T1110": "Credential Access", "T1528": "Credential Access",
    "T1539": "Credential Access", "T1552": "Credential Access",
    "T1555": "Credential Access", "T1556": "Credential Access",
    "T1557": "Credential Access",
    "T1018": "Discovery", "T1033": "Discovery", "T1046": "Discovery",
    "T1049": "Discovery", "T1057": "Discovery", "T1069": "Discovery",
    "T1082": "Discovery", "T1083": "Discovery", "T1087": "Discovery",
    "T1518": "Discovery", "T1526": "Discovery", "T1613": "Discovery",
    "T1021": "Lateral Movement", "T1072": "Lateral Movement",
    "T1210": "Lateral Movement", "T1563": "Lateral Movement",
    "T1570": "Lateral Movement",
    "T1005": "Collection", "T1074": "Collection", "T1560": "Collection",
    "T1071": "Command and Control", "T1090": "Command and Control",
    "T1095": "Command and Control", "T1104": "Command and Control",
    "T1105": "Command and Control", "T1132": "Command and Control",
    "T1219": "Command and Control", "T1571": "Command and Control",
    "T1572": "Command and Control", "T1573": "Command and Control",
    "T1041": "Exfiltration", "T1048": "Exfiltration", "T1567": "Exfiltration",
    "T1485": "Impact", "T1486": "Impact", "T1489": "Impact",
    "T1490": "Impact", "T1495": "Impact", "T1496": "Impact",
    "T1499": "Impact", "T1531": "Impact", "T1561": "Impact",
    "T1565": "Impact",
}

# Left to right as ATT&CK draws it, so the matrix reads as an attack sequence.
ATTACK_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact", "Other",
]

APP_CSS = """
:root{--bg:#0f1419;--panel:#161b22;--panel2:#1c2330;--line:#2b3440;--fg:#d7dee7;
--dim:#8b98a8;--accent:#58a6ff;--gold:#f5d067;
--CRITICAL:#ff5f56;--HIGH:#ff9f43;--MEDIUM:#ffd93d;--LOW:#5ad1e6;--INFO:#8b98a8}
*{box-sizing:border-box}
body{margin:0;font:13px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
background:var(--bg);color:var(--fg);overflow:hidden}
code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace}
a{color:var(--accent);text-decoration:none}

/* ---- chrome ---- */
header{display:flex;align-items:center;gap:16px;padding:10px 16px;
border-bottom:1px solid var(--line);background:var(--panel);height:56px}
.brand{display:flex;align-items:baseline;gap:9px;flex:0 0 auto}
.brand b{font-size:17px;font-weight:600;letter-spacing:-.3px}
.brand span{font-size:9.5px;letter-spacing:2px;color:var(--dim)}
.host{color:var(--dim);font-size:12px;overflow:hidden;text-overflow:ellipsis;
white-space:nowrap;flex:1 1 auto}
.host b{color:var(--fg);font-weight:600}
.chips{display:flex;gap:6px;flex:0 0 auto}
.chip{border:1px solid var(--line);border-radius:14px;padding:2px 10px;cursor:pointer;
font-size:11px;letter-spacing:.5px;background:transparent;color:var(--dim);
font-variant-numeric:tabular-nums;user-select:none}
.chip b{color:var(--fg);margin-right:5px}
.chip.on{background:var(--panel2)}
.chip.on.CRITICAL{color:var(--CRITICAL);border-color:var(--CRITICAL)}
.chip.on.HIGH{color:var(--HIGH);border-color:var(--HIGH)}
.chip.on.MEDIUM{color:var(--MEDIUM);border-color:var(--MEDIUM)}
.chip.on.LOW{color:var(--LOW);border-color:var(--LOW)}
.chip.on.INFO{color:var(--INFO);border-color:var(--INFO)}
.chip.off{opacity:.42;text-decoration:line-through}
/* the time window, beside the chips: the other filter that bites everywhere */
.tf{display:flex;align-items:center;gap:4px;flex:0 0 auto}
.tf input{width:104px;background:var(--panel2);color:var(--fg);border:1px solid var(--line);
border-radius:4px;padding:2px 6px;font:11px/1.6 inherit;outline:none}
.tf input:focus{border-color:var(--accent)}
.tf input.on{border-color:var(--gold);color:var(--gold)}
.tf input.bad{border-color:var(--CRITICAL);color:var(--CRITICAL)}
.tf .ar{color:var(--dim);font-size:11px}
.tf button.clr{padding:1px 7px;line-height:1.4}
.tf button.clr.on{color:var(--gold);border-color:var(--gold)}
/* ---- the calendar ----
   A month grid rather than a native date input: this one shades the days that
   actually carry evidence, which is the thing a reader wants to know before
   picking one. A collection is mostly empty days and three loud ones. */
.cal{display:none;position:fixed;z-index:40;background:var(--panel);
border:1px solid var(--line);border-radius:8px;padding:10px;width:246px;
box-shadow:0 10px 30px rgba(0,0,0,.45)}
.cal.open{display:block}
.cal .hd{display:flex;align-items:center;justify-content:space-between;
margin-bottom:8px}
.cal .hd b{font-size:12px;font-weight:600;letter-spacing:.3px}
.cal .nav{background:transparent;border:1px solid var(--line);border-radius:4px;
color:var(--dim);cursor:pointer;width:22px;height:22px;line-height:1;font-size:13px}
.cal .nav:hover{color:var(--accent);border-color:var(--accent)}
.cal .grid{display:grid;grid-template-columns:repeat(7,1fr);gap:2px}
.cal .wd{color:var(--dim);font-size:9.5px;text-align:center;letter-spacing:.5px;
padding-bottom:2px}
.cal .d{position:relative;height:26px;border-radius:4px;border:1px solid transparent;
display:flex;align-items:center;justify-content:center;font-size:11.5px;
font-variant-numeric:tabular-nums;cursor:pointer;color:var(--fg)}
.cal .d.pad{color:var(--dim);opacity:.35;cursor:default}
.cal .d:not(.pad):hover{border-color:var(--gold)}
/* the day's own evidence, behind the number rather than replacing it */
.cal .d .lvl{position:absolute;left:0;right:0;top:0;bottom:0;border-radius:4px;
background:var(--accent);z-index:0}
.cal .d span{position:relative;z-index:1}
.cal .d.in .lvl{background:var(--gold)}
.cal .d.edge{border-color:var(--gold);font-weight:700}
.cal .d.none{color:var(--dim);opacity:.55}
.cal .ft{display:flex;align-items:center;gap:6px;margin-top:9px;
border-top:1px solid var(--line);padding-top:8px}
.cal .ft input{width:62px;background:var(--bg);color:var(--fg);border:1px solid var(--line);
border-radius:4px;padding:2px 5px;font:11px/1.5 inherit;outline:none;text-align:center}
.cal .ft input:focus{border-color:var(--accent)}
.cal .ft .lb{color:var(--dim);font-size:10.5px}
.cal .pre{display:flex;flex-wrap:wrap;gap:4px;margin-top:8px}
.cal .pre button{flex:1 1 auto;background:var(--bg);border:1px solid var(--line);
color:var(--dim);border-radius:11px;padding:2px 6px;font-size:10.5px;cursor:pointer}
.cal .pre button:hover{color:var(--gold);border-color:var(--gold)}

.layout{display:flex;height:calc(100vh - 56px)}
nav{width:248px;flex:0 0 248px;background:var(--panel);border-right:1px solid var(--line);
padding:10px 0;display:flex;flex-direction:column;overflow-y:auto}
nav a{display:flex;justify-content:space-between;align-items:center;gap:8px;
padding:7px 14px;color:var(--fg);border-left:3px solid transparent;cursor:pointer}
nav a:hover{background:var(--panel2)}
nav a.active{background:var(--panel2);border-left-color:var(--gold);color:var(--gold)}
nav a .n{color:var(--dim);font-size:11px;font-variant-numeric:tabular-nums}
nav .foot{margin-top:auto;padding:10px 14px;color:var(--dim);font-size:10.5px;
border-top:1px solid var(--line)}
main{flex:1;overflow:auto;padding:16px 18px;min-width:0}
h2{margin:0 0 12px;font-size:14px;font-weight:600;letter-spacing:.3px}
h3{margin:22px 0 9px;font-size:12px;font-weight:600;color:var(--dim);
text-transform:uppercase;letter-spacing:1px}

/* ---- overview ---- */
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:6px}
.card{flex:1 1 128px;background:var(--panel);border:1px solid var(--line);
border-top-width:3px;border-radius:6px;padding:11px 13px;cursor:pointer}
.card:hover{background:var(--panel2)}
.card b{display:block;font-size:25px;line-height:1.15;font-variant-numeric:tabular-nums}
.card span{color:var(--dim);font-size:10.5px;letter-spacing:1.1px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:18px}
.bars{display:flex;flex-direction:column;gap:5px}
.bar{display:grid;grid-template-columns:1fr 46px;gap:9px;align-items:center;cursor:pointer}
.bar:hover .lbl{color:var(--gold)}
.bar .lbl{position:relative;padding:3px 7px;overflow:hidden;text-overflow:ellipsis;
white-space:nowrap;border-radius:3px;background:var(--panel)}
.bar .fill{position:absolute;left:0;top:0;bottom:0;background:var(--panel2);z-index:0}
.bar .tx{position:relative;z-index:1}
.bar .n{text-align:right;color:var(--dim);font-variant-numeric:tabular-nums}
.histo{display:flex;align-items:flex-end;gap:2px;background:var(--panel);
border:1px solid var(--line);border-radius:6px;padding:8px}
.histo .col{flex:1;min-width:2px;height:100%;display:flex;flex-direction:column-reverse}
.histo .col:hover{outline:1px solid var(--gold);outline-offset:1px}
.histo.click .col{cursor:pointer}
/* A bucket holding one event still has to be visible next to a bucket holding
   a thousand, or a quiet week reads as no data at all. */
.histo .seg{width:100%;opacity:.85;min-height:2px}
.histo .col:hover .seg{opacity:1}
.histo .col.on{outline:1px solid var(--gold)}
.axis{display:flex;justify-content:space-between;color:var(--dim);font-size:10.5px;
padding:4px 2px 0}
/* seven rows of twenty-four cells, plus a label column and an hour axis that
   spans the cells rather than the label */
.heat{display:grid;grid-template-columns:30px repeat(24,1fr);gap:2px;
background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:8px}
.heat .d{color:var(--dim);font-size:10px;line-height:15px;text-align:right;
padding-right:5px}
.heat .c{height:15px;border-radius:2px;background:#1a212b}
.heat .c.on{cursor:default}
.heat .c.on:hover{outline:1px solid var(--gold);outline-offset:1px}
.heat .hx{grid-column:2/26;display:flex;justify-content:space-between;
color:var(--dim);font-size:10.5px;padding-top:5px}
table.meta{border-collapse:collapse;font-size:12px}
table.meta td{padding:3px 14px 3px 0;vertical-align:top;border:0}
table.meta td:first-child{color:var(--dim);white-space:nowrap}

/* ---- findings ----
   The findings list is the FINDINGS grid itself; this is the pane that opens
   above it for the row under the cursor. */
.detail{position:relative;max-height:44vh;overflow:auto;border:1px solid var(--line);
border-radius:6px;background:var(--panel);padding:14px 16px;margin:0 0 10px}
.detail .x{position:absolute;right:11px;top:7px;cursor:pointer;color:var(--dim);
font-size:17px;line-height:1}
.detail .x:hover{color:var(--fg)}
.pills{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 9px}
.pills:empty{display:none}
.tbl tbody tr.sel td{background:#233043;box-shadow:inset 3px 0 0 var(--gold)}
.detail h4{margin:0 0 6px;font-size:14px;font-weight:600}
.detail .d{color:var(--dim);margin-bottom:12px}
.detail pre{background:var(--bg);border:1px solid var(--line);border-radius:5px;
padding:10px;overflow:auto;max-height:52vh;font-size:11.5px;white-space:pre-wrap;
word-break:break-all;margin:0}
.kv{display:grid;grid-template-columns:92px 1fr;gap:4px 12px;margin-bottom:13px;
font-size:12px}
.kv span{color:var(--dim)}
.pill{display:inline-block;border:1px solid var(--line);border-radius:11px;
padding:0 8px;margin:0 4px 4px 0;font-size:11px;cursor:pointer;color:var(--accent)}
.pill:hover{background:var(--panel2)}
.empty{color:var(--dim);padding:26px 4px;text-align:center}
.bartop{display:flex;gap:8px;align-items:center;margin-bottom:10px}
.card2{background:var(--panel);border:1px solid var(--line);border-radius:6px;
 padding:10px 12px;margin:10px 0}
.card2 a.gs{cursor:pointer;color:var(--accent);text-decoration:none}
.card2 a.gs:hover{text-decoration:underline}
table.mini{width:100%;margin-top:8px;border-collapse:collapse;font-size:12px;
 table-layout:fixed}
table.mini th{text-align:left;color:var(--dim);font-weight:normal;
 border-bottom:1px solid var(--line);padding:3px 6px}
table.mini td{padding:3px 6px;border-bottom:1px solid var(--line);
 overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
input[type=search],select{background:var(--panel);color:var(--fg);
border:1px solid var(--line);border-radius:5px;padding:5px 9px;font:inherit;outline:none}
input[type=search]{flex:1}
input[type=search]:focus,select:focus{border-color:var(--accent)}
.count{color:var(--dim);font-size:11.5px;white-space:nowrap}

/* ---- attack matrix ---- */
.matrix{display:flex;gap:8px;overflow-x:auto;padding-bottom:8px;align-items:flex-start}
.tac{flex:0 0 152px;background:var(--panel);border:1px solid var(--line);border-radius:6px}
.tac .h{padding:7px 9px;border-bottom:1px solid var(--line);font-size:10.5px;
color:var(--dim);text-transform:uppercase;letter-spacing:.8px;line-height:1.3}
.tac .h b{display:block;color:var(--fg);font-size:11.5px;letter-spacing:0;
text-transform:none}
.cell{margin:6px;padding:5px 7px;border-radius:4px;cursor:pointer;
border-left:3px solid var(--line);background:var(--panel2)}
.cell:hover{outline:1px solid var(--gold)}
.cell .id{font-size:11px;font-variant-numeric:tabular-nums}
.cell .nm{color:var(--dim);font-size:10.5px;overflow:hidden;text-overflow:ellipsis;
white-space:nowrap}
.cell .n{float:right;color:var(--dim);font-size:10.5px}

/* ---- tables (timeline, and the console's own grids) ---- */
table.grid{width:100%;border-collapse:collapse;font-size:12px}
table.grid th{position:sticky;top:0;background:var(--panel2);text-align:left;
padding:6px 9px;border-bottom:1px solid var(--line);font-weight:600;z-index:1}
table.grid td{padding:4px 9px;border-bottom:1px solid var(--line);vertical-align:top}
table.grid tr:hover td{background:var(--panel)}
td.mono{font-family:ui-monospace,Consolas,monospace;white-space:nowrap}
td.wrap{word-break:break-word}
.more{margin:12px 0;padding:7px;text-align:center;border:1px dashed var(--line);
border-radius:5px;color:var(--dim);cursor:pointer}
.more:hover{color:var(--fg);border-color:var(--accent)}
/* nav: the five views, then every table under its category */
nav .cat{padding:12px 14px 4px;color:var(--dim);font-size:10px;text-transform:uppercase;
letter-spacing:1px}
nav .sec{margin-top:6px;border-top:1px solid var(--line);padding-top:4px}
nav a.tbl{padding:5px 14px;font-size:12px}
nav a.tbl span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* ---- tables ----
   Scoped to .tbl: the console has tables of its own (the timeline and
   the collection metadata) and fixed layout with measured column widths is
   right for an artifact grid and wrong for those. */
.desc{color:var(--dim);margin:0 0 12px;font-size:12px}
.controls{display:flex;gap:8px;align-items:center;margin-bottom:10px;flex-wrap:wrap}
.badge{background:#0d1117;border:1px solid var(--line);border-radius:11px;padding:2px 9px;
color:var(--dim);font-size:11px;white-space:nowrap}
.warn{color:var(--HIGH)}
/* fixed layout so the <colgroup> widths computed from the data are what the
   browser actually uses - with auto layout one long cell drags its column
   wide and squeezes every other column into a ragged strip */
/* min-width so a narrow table still fills the pane - fixed layout then shares
   the spare width across the columns instead of leaving a ragged right edge */
table.tbl{border-collapse:collapse;font-size:12px;table-layout:fixed;min-width:100%}
.tbl th,.tbl td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top;
overflow-wrap:anywhere}
/* a cell taller than this scrolls inside itself, so one 4000-character
   evidence blob cannot push the next row off the screen */
.tbl td .c{white-space:pre-wrap;max-height:8.5em;overflow-y:auto}
.tbl td.nw .c{white-space:nowrap;overflow-x:hidden;text-overflow:ellipsis}
.tbl td.nw:hover .c{overflow-x:auto;text-overflow:clip}
.tbl th{background:#1c2330;position:sticky;top:0;z-index:4;cursor:pointer;user-select:none;
white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tbl th:hover{color:var(--accent)}
/* the per-column filter row sits directly under the labels; its offset is set
   from the measured label height in wire(), because the two rows have to stay
   glued together when the body scrolls under them */
.tbl tr.f th{background:var(--panel);padding:3px 4px;cursor:auto;z-index:3}
.tbl tr.f th:hover{color:inherit}
.tbl tr.f input{width:100%;background:#0d1117;border:1px solid var(--line);color:var(--fg);
border-radius:3px;padding:2px 5px;font:11px/1.5 inherit}
.tbl tr.f input:focus{outline:none;border-color:var(--accent)}
.tbl tr.f input.on{border-color:var(--accent);background:#10243d;color:#fff}
button.clr{background:#0d1117;border:1px solid var(--line);color:var(--dim);
border-radius:11px;padding:2px 9px;font-size:11px;cursor:pointer}
button.clr:hover{color:var(--accent);border-color:var(--accent)}
.tbl tbody tr:nth-child(even){background:#12171e}
.tbl tbody tr:hover{background:#1a212b}
.tbl td.num{text-align:right;font-variant-numeric:tabular-nums}
.sev-CRITICAL{color:var(--CRITICAL);font-weight:600}
.sev-HIGH{color:var(--HIGH);font-weight:600}
.sev-MEDIUM{color:var(--MEDIUM)}
.sev-LOW{color:var(--LOW)}
.sev-INFO{color:var(--INFO)}
"""

APP_JS = """var D=window.__LINSIGHT__,SEV=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
var TB=D.tables||{},IDX=D.index||[],V=D.views||{},PIN=D.pinned||[];
/* Rows for the large tables, gzipped and base64'd, one entry per table.

   The page carries every row of the export so that a search across all
   tables is a search across all the evidence - which on a real collection is
   three quarters of a million rows and, written as plain JSON, a 228 MB
   file that a browser will not open in any reasonable time. Compressed it is
   14 MB, and decoded a table at a time, when that table is first read.

   Small tables are not in here at all: they are inline in D.tables, so the
   findings, the timeline and the forty-odd little grids need no decoder. */
var PACK=window.__ROWS__||{},GZ_OK=(typeof DecompressionStream!=='undefined');
var PENDING={};
function unpack(b64){
 var bin=atob(b64),u=new Uint8Array(bin.length);
 for(var i=0;i<bin.length;i++)u[i]=bin.charCodeAt(i);
 var st=new Blob([u]).stream().pipeThrough(new DecompressionStream('gzip'));
 return new Response(st).text().then(function(txt){return JSON.parse(txt);});
}
/* Resolves once every named table has its rows. Decodes run once per table
   and are shared: opening a grid while the same table is already being
   decoded for a search must not decode it twice. */
function ensure(names){
 var want=[];
 (names||[]).forEach(function(n){
  var t=TB[n];
  if(!t||t.rows!==undefined||!PACK[n])return;
  if(want.indexOf(n)<0)want.push(n);});
 if(!want.length)return Promise.resolve();
 if(!GZ_OK){
  want.forEach(function(n){TB[n].rows=[];TB[n].no_gzip=true;});
  return Promise.resolve();
 }
 return Promise.all(want.map(function(n){
  if(!PENDING[n]){
   PENDING[n]=unpack(PACK[n]).then(function(rows){
    TB[n].rows=rows;delete PACK[n];
   },function(err){
    TB[n].rows=[];TB[n].decode_error=String(err&&err.message||err);});
  }
  return PENDING[n];}));
}
/* Which tables the view about to be drawn actually reads. The console views
   are computed from FINDINGS and TIMELINE, the overview also ranks a handful
   of named grids, and the search reads everything by definition. */
function needs(){
 var n=[],k;
 for(k in V)n.push(V[k]);
 if(TB[HT])n.push(HT);
 RANKED.forEach(function(r){n.push(r[0]);});
 if(st.table)n.push(st.table);
 if(st.view==='search')for(k in TB)n.push(k);
 return n;
}
/* The offensive-tool grid the overview reads and the nav pins. Named once:
   the console asks for it in four places and a typo would fail silently. */
var HT='HACKTOOL_HITS';
var st={view:null,sev:{},cat:'',tech:'',sel:null,table:null,tq:'',gq:'',
        t0:null,t1:null};   /* t0/t1: the time window, epoch seconds, inclusive */
SEV.forEach(function(s){st.sev[s]=true;});
var VIEWS=[['overview','Overview'],['findings','Findings'],['attack','ATT&CK'],
           ['timeline','Timeline'],['search','Search all']];

function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){
 return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function el(id){return document.getElementById(id);}
function sevRank(s){var i=SEV.indexOf(s);return i<0?99:i;}

/* The console views ARE the analysis tables - there is one FINDINGS and one
   TIMELINE, and the view is how you read it. Nothing is carried twice: the
   severity cards, the ATT&CK matrix, the activity charts and the offensive-
   tool ranking are all computed from these rows and from HACKTOOL_HITS,
   rather than from a second copy of the same data embedded beside them. */
function vt(v){return V[v]&&TB[V[v]]?TB[V[v]]:null;}
function isView(t){
 for(var k in V){if(V[k]===t.name)return k;}
 return null;
}
function ci(t,name){return t?t.columns.indexOf(name):-1;}
/* '2026-03-24 16:03:05' -> epoch seconds. The column is UTC by construction
   (every clock is normalised before it reaches a table), so it is read as UTC
   rather than through the examiner's timezone. */
function ts(s){
 var d=Date.parse(String(s||'').replace(' ','T')+'Z');
 return isNaN(d)?null:d/1000;
}

/* ---------- the time window ---------- */
/* One window, applied to every grid that carries a clock rather than only to
   the three console views. 'what happened between 03:00 and 04:00' is the
   question a triage console exists to answer, and answering it in FINDINGS
   while AUTH_LOG and WEB_LOG still show the whole capture is not an answer.

   A table with no time column is left alone rather than emptied: /etc/passwd
   did not happen at a time, and a window that blanks the account list has
   filtered out the context you narrowed in order to read. */
var TCOL=D.tcols||['timestamp_utc'],SPAN=D.spancols||['first_utc','last_utc'];
function tcols(t){
 if(t._tc)return t._tc;
 var i,p=-1;
 for(i=0;i<TCOL.length&&p<0;i++)p=ci(t,TCOL[i]);
 var f=ci(t,SPAN[0]),l=ci(t,SPAN[1]);
 t._tc={p:p,f:f,l:l,any:(p>=0||f>=0||l>=0)};
 return t._tc;
}
/* A row's own extent: a stamp is a point, first/last is a span, and a row
   carrying both is placed at its stamp. Returns null for a row that is
   simply undated - a finding raised off a config file has no time, and that
   is a fact about the finding rather than a parse failure. */
function rowSpan(tc,r){
 var a=null,b=null;
 if(tc.p>=0)a=b=ts(r[tc.p]);
 if(a===null&&tc.f>=0)a=ts(r[tc.f]);
 if(b===null&&tc.l>=0)b=ts(r[tc.l]);
 if(a===null&&b===null)return null;
 if(a===null)a=b;
 if(b===null)b=a;
 return b<a?[b,a]:[a,b];
}
/* Overlap, not containment: a finding that ran from 02:00 to 05:00 happened
   during a window of 03:00-04:00, and requiring the whole span to fit inside
   would drop exactly the long-running things worth narrowing onto. */
function inWindow(tc,r){
 var sp=rowSpan(tc,r);
 if(sp===null)return false;
 if(st.t0!==null&&sp[1]<st.t0)return false;
 if(st.t1!==null&&sp[0]>st.t1)return false;
 return true;
}
function winOn(){return st.t0!==null||st.t1!==null;}
/* The latest moment anything in the collection carries, so '-24h' has an end
   to count back from. The capture is the natural anchor, not the reader's
   clock: a collection taken last year is still read as its own last day. */
var DMAX=null;
function dataMax(){
 if(DMAX!==null)return DMAX;
 DMAX=0;
 var t=vt('timeline')||vt('findings');
 if(t){
  var tc=tcols(t);
  t.rows.forEach(function(r){
   var sp=rowSpan(tc,r);
   if(sp&&sp[1]>DMAX)DMAX=sp[1];});}
 return DMAX;
}
/* 'YYYY-MM-DD', with an optional time, or '-24h' / '-7d' / '-2w' counted back
   from the end of the data. `end` rounds a bare date up to its last second,
   so 'to: 2021-12-08' means all of the 8th rather than midnight at its start.
   Returns undefined for text that is not a time at all, which is how the box
   knows to mark itself bad instead of silently filtering nothing. */
function parseWhen(txt,end){
 var v=String(txt||'').trim();
 if(!v)return null;
 var rel=/^-(\\d+)\\s*([hdw])$/i.exec(v);
 if(rel){
  var mul={h:3600,d:86400,w:604800}[rel[2].toLowerCase()];
  var base=dataMax();
  return base?base-(+rel[1])*mul:undefined;
 }
 var m=/^(\\d{4})-(\\d\\d)-(\\d\\d)(?:[ T](\\d\\d):(\\d\\d)(?::(\\d\\d))?)?$/.exec(v);
 if(!m)return undefined;
 var hasT=m[4]!==undefined,hasS=m[6]!==undefined;
 var d=Date.UTC(+m[1],+m[2]-1,+m[3],hasT?+m[4]:0,hasT?+m[5]:0,hasS?+m[6]:0);
 if(isNaN(d))return undefined;
 var sec=d/1000;
 if(!end)return sec;
 return sec+(hasS?0:(hasT?59:86399));
}
function fmtWin(){
 return (st.t0!==null?fmtT(st.t0):'\u2026')+' \u2192 '+
        (st.t1!==null?fmtT(st.t1):'\u2026');
}
function setWin(a,b){
 st.t0=a;st.t1=b;
 var i0=el('t0'),i1=el('t1');
 if(i0)i0.value=a===null?'':fmtT(a);
 if(i1)i1.value=b===null?'':fmtT(b);
 markWin();
 render();
}
function markWin(){
 var i0=el('t0'),i1=el('t1'),c=el('tclr');
 if(i0)i0.classList.toggle('on',st.t0!==null);
 if(i1)i1.classList.toggle('on',st.t1!==null);
 if(c)c.classList.toggle('on',winOn());
}
/* Typed into either box: both are re-read, because '-24h' in the from box is
   defined against whatever the to box says. A box holding text that is not a
   time marks itself and is treated as empty rather than emptying the grid. */
function readWin(){
 var i0=el('t0'),i1=el('t1');
 var a=parseWhen(i0?i0.value:'',false),b=parseWhen(i1?i1.value:'',true);
 if(i0)i0.classList.toggle('bad',a===undefined);
 if(i1)i1.classList.toggle('bad',b===undefined);
 st.t0=(a===undefined)?null:a;
 st.t1=(b===undefined)?null:b;
 markWin();
 render();
}
/* How many rows the window took out of this grid because they carry no time
   at all - worth saying, because 55 of 104 findings are undated and a reader
   who does not know that reads their absence as 'nothing happened'. */
function undatedCount(t){
 var tc=tcols(t);
 if(!tc.any)return 0;
 var n=0;
 t.rows.forEach(function(r){if(rowSpan(tc,r)===null)n++;});
 return n;
}
function winBadge(t){
 if(!winOn())return '';
 var tc=tcols(t);
 if(!tc.any)return '<span class="badge">time window not applied \u2014 '+
   esc(t.name)+' carries no clock</span>';
 var u=undatedCount(t);
 return '<span class="badge warn">window '+esc(fmtWin())+
   (u?' \u2014 '+u.toLocaleString()+' undated row(s) hidden':'')+
   ' <span class="pill" data-winclear="1">clear &times;</span></span>';
}

var TECH=/\\bT\\d{4}(?:\\.\\d{3})?\\b/g;
function techsOf(s){return String(s||'').match(TECH)||[];}
/* The name beside an ID, taken from the cell itself: 'T1053.003 Scheduled
   Task: Cron' -> 'Scheduled Task: Cron'. A bare ID keeps no name rather than
   being given an invented one. */
function techName(mitre,t){
 var s=String(mitre||''),i=s.indexOf(t);
 if(i<0)return '';
 var rest=s.slice(i+t.length).replace(/^[\\s\\-:]+/,'').split('/')[0].split(',')[0].trim();
 return TECH.test(rest)?'':rest.slice(0,60);
}
function tacticOf(t){return D.tactics[t.split('.')[0]]||'Other';}

/* Column indexes for the findings table, resolved once. */
var F=null;
function fc(){
 var t=vt('findings');
 if(!t)return null;
 if(F&&F.t===t)return F;
 F={t:t};
 ['severity','category','title','mitre','artifact','count','first_utc',
  'last_utc','detail','evidence_count','evidence'].forEach(function(c){
   F[c]=ci(t,c);});
 return F;
}
/* Findings under the header chips and the category / technique pills. The
   row search box is deliberately NOT applied here: it belongs to the grid
   being typed into, and the overview should not empty itself because a
   filter was left behind in another view. */
function frows(){
 var f=fc();
 if(!f)return [];
 var tc=winOn()?tcols(f.t):null;
 return f.t.rows.filter(function(r){
  if(!st.sev[r[f.severity]])return false;
  if(st.cat&&r[f.category]!==st.cat)return false;
  if(st.tech&&techsOf(r[f.mitre]).indexOf(st.tech)<0)return false;
  if(tc&&tc.any&&!inWindow(tc,r))return false;
  return true;});
}

function setView(v,name){
 if(v==='table'){
  if(name!==st.table){st.table=name;sortCol=-1;colFilters=[];st.tq='';}
 }else if(vt(v)){
  /* A console view is a table too, so switching to one carries the same
     reset: its sort and its column filters are its own. */
  var n=V[v];
  if(n!==st.table){st.table=n;sortCol=-1;colFilters=[];st.tq='';}
 }
 st.view=v;
 location.hash=(v==='table')?'t/'+st.table:v;
 render();
}
function markNav(){
 [].forEach.call(document.querySelectorAll('nav a'),function(a){
  a.classList.toggle('active',st.view==='table'
   ?a.getAttribute('data-t')===st.table
   :a.getAttribute('data-v')===st.view);});
}
function chips(){
 var f=fc();
 if(!f){el('chips').innerHTML='';return;}
 var n={};
 (f.t.rows||[]).forEach(function(r){n[r[f.severity]]=(n[r[f.severity]]||0)+1;});
 var h='';
 SEV.forEach(function(s){
  h+='<button class="chip '+s+' '+(st.sev[s]?'on':'off')+'" data-s="'+s+'">'+
     '<b>'+(n[s]||0)+'</b>'+s+'</button>';});
 el('chips').innerHTML=h;
 [].forEach.call(document.querySelectorAll('#chips .chip'),function(b){
  b.onclick=function(ev){
   ev=ev||window.event;
   var s=b.getAttribute('data-s');
   /* Alt-click isolates one severity - the common move is "only the
      criticals", which is otherwise four clicks. */
   if(ev&&ev.altKey){SEV.forEach(function(x){st.sev[x]=(x===s);});}
   else{st.sev[s]=!st.sev[s];}
   chips();render();};});
}

/* ---------- charts ---------- */
/* Rows bucketed into n columns between the first and last timestamp, each
   column a stack of severity segments. Buckets rather than one bar per row: a
   collection covering a year and one covering an hour have to produce the
   same shaped chart, and the stack is what makes a burst of CRITICAL visible
   inside an hour that also carries a thousand INFO lines. */
/* The bucket bounds of the last histogram drawn with clickable:true, so the
   click handler can turn a column index back into a time range. */
var HB=[];
function histo(rows,ti,si,n,h_px,clickable){
 var pts=[];
 rows.forEach(function(r){
  var e=ts(r[ti]);
  if(e!==null)pts.push([e,si>=0?r[si]:'INFO']);});
 if(!pts.length)return {html:'<div class="empty">no dated rows</div>',b:[]};
 var t0=pts[0][0],t1=t0,i;
 pts.forEach(function(p){if(p[0]<t0)t0=p[0];if(p[0]>t1)t1=p[0];});
 var span=Math.max(1,t1-t0),b=[];
 for(i=0;i<n;i++)b.push({n:0,s:{},t0:t0+span*i/n,t1:t0+span*(i+1)/n});
 pts.forEach(function(p){
  var k=Math.max(0,Math.min(n-1,Math.floor((p[0]-t0)*n/span)));
  b[k].n++;b[k].s[p[1]]=(b[k].s[p[1]]||0)+1;});
 var max=0;
 b.forEach(function(x){if(x.n>max)max=x.n;});
 max=max||1;
 var h='<div class="histo'+(clickable?' click':'')+'" style="height:'+h_px+'px">';
 for(i=0;i<n;i++){
  var tip=[];
  SEV.forEach(function(sv){if(b[i].s[sv])tip.push(b[i].s[sv]+' '+sv);});
  /* A column is lit when it overlaps the window, not when it was the one
     clicked: the window can also be typed, or set from another chart, and a
     highlight that only followed clicks would disagree with the filter. */
  var lit=clickable&&winOn()&&
    !(st.t1!==null&&b[i].t0>st.t1)&&!(st.t0!==null&&b[i].t1<st.t0);
  h+='<div class="col'+(lit?' on':'')+'" data-b="'+i+
     '" title="'+esc(fmtT(b[i].t0)+'  -  '+(tip.join(', ')||'0'))+'">';
  /* column-reverse stacks the first child at the bottom, so walking INFO up
     to CRITICAL puts the loud severities on top where they are read first. */
  for(var j=SEV.length-1;j>=0;j--){
   var c=b[i].s[SEV[j]];
   if(c)h+='<div class="seg" style="height:'+(c*100/max)+'%;background:var(--'+
     SEV[j]+')"></div>';}
  h+='</div>';}
 h+='</div><div class="axis"><span>'+esc(fmtT(t0))+'</span><span>'+
    esc(fmtT(t0+span/2))+'</span><span>'+esc(fmtT(t1))+'</span></div>';
 if(clickable)HB=b;
 return {html:h,b:b};
}
/* Epoch seconds back to the shape the rows carry, built from the UTC parts
   rather than the locale: the whole report is UTC and an axis that quietly
   shifts to the examiner's timezone is a wrong answer. */
function fmtT(sec){
 var d=new Date(sec*1000),p=function(x){return (x<10?'0':'')+x;};
 return d.getUTCFullYear()+'-'+p(d.getUTCMonth()+1)+'-'+p(d.getUTCDate())+' '+
        p(d.getUTCHours())+':'+p(d.getUTCMinutes());
}
/* 24 UTC hours, severity-stacked. This answers what the running timeline
   cannot: whether the activity sits inside a working day or at 03:00. A month
   of evidence collapses onto one clock face, so a nightly cron and a single
   3am login land in the same column and the shape is the question. */
function hourly(rows,ti,si,h_px){
 var b=[],i,any=false;
 for(i=0;i<24;i++)b.push({n:0,s:{}});
 rows.forEach(function(r){
  var e=ts(r[ti]);
  if(e===null)return;
  any=true;
  var k=new Date(e*1000).getUTCHours(),sv=si>=0?r[si]:'INFO';
  b[k].n++;b[k].s[sv]=(b[k].s[sv]||0)+1;});
 if(!any)return '<div class="empty">no dated rows</div>';
 var max=0;
 b.forEach(function(x){if(x.n>max)max=x.n;});
 max=max||1;
 var h='<div class="histo" style="height:'+h_px+'px">';
 for(i=0;i<24;i++){
  var tip=[];
  SEV.forEach(function(sv){if(b[i].s[sv])tip.push(b[i].s[sv]+' '+sv);});
  h+='<div class="col" title="'+esc((i<10?'0':'')+i+':00 UTC  -  '+
     (tip.join(', ')||'0'))+'">';
  for(var j=SEV.length-1;j>=0;j--){
   var c=b[i].s[SEV[j]];
   if(c)h+='<div class="seg" style="height:'+(c*100/max)+'%;background:var(--'+
     SEV[j]+')"></div>';}
  h+='</div>';}
 return h+'</div><div class="axis"><span>00:00</span><span>06:00</span>'+
   '<span>12:00</span><span>18:00</span><span>23:00</span></div>';
}
/* A pair may carry a third element, a severity, and a bar that has one is
   tinted with it. Length alone ranks by how often a name was seen, which puts
   a noisy LOW above the single CRITICAL hit that is the reason to look. */
function barList(pairs,act,lab){
 if(!pairs.length)return '<div class="empty">nothing</div>';
 /* the largest value, not the first one: a list ranked by severity rather
    than by length puts a short bar at the head, and scaling to it draws every
    longer bar past the full width of its own track */
 var max=1,h='<div class="bars">';
 pairs.forEach(function(p){if(p[1]>max)max=p[1];});
 pairs.forEach(function(p){
  var tint=p[2]?';background:var(--'+p[2]+');opacity:.32':'';
  h+='<div class="bar" data-k="'+esc(p[0])+'" data-act="'+(act||'')+'">'+
     '<div class="lbl"><div class="fill" style="width:'+
     Math.max(2,Math.round(p[1]*100/max))+'%'+tint+'"></div>'+
     '<div class="tx">'+esc((lab?lab(p[0]):p[0])||'(none)')+'</div></div>'+
     '<div class="n">'+p[1]+'</div></div>';});
 return h+'</div>';
}
function uniq(a){
 var seen={},out=[];
 a.forEach(function(x){if(!seen[x]){seen[x]=1;out.push(x);}});
 return out;
}
/* Seven days by twenty-four hours. This is the shape a single hour profile
   cannot show: a job that runs every night at 03:00 draws a column, a weekend
   intrusion draws two rows, and a one-off draws a single cell. Intensity is
   volume and the colour is the worst severity in the cell, because the quiet
   cell holding the only CRITICAL row is the one worth finding.

   sqrt on the intensity, not a linear ramp: one artifact that logs every
   minute sets max for the whole grid, and everything else would sit at the
   same invisible floor under it. */
var DAYS=['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
function heat(rows,ti,si){
 var g=[],d,i,any=false,max=0;
 for(d=0;d<7;d++){g.push([]);for(i=0;i<24;i++)g[d].push({n:0,s:'INFO'});}
 rows.forEach(function(r){
  var e=ts(r[ti]);
  if(e===null)return;
  any=true;
  var dt=new Date(e*1000),c=g[(dt.getUTCDay()+6)%7][dt.getUTCHours()];
  c.n++;
  if(c.n>max)max=c.n;
  var sv=si>=0?r[si]:'INFO';
  if(sevRank(sv)<sevRank(c.s))c.s=sv;});
 if(!any)return '<div class="empty">no dated rows</div>';
 var h='<div class="heat">';
 for(d=0;d<7;d++){
  h+='<div class="d">'+DAYS[d]+'</div>';
  for(i=0;i<24;i++){
   var c=g[d][i];
   var sty=c.n?' style="background:var(--'+c.s+');opacity:'+
     (0.2+0.8*Math.sqrt(c.n/max)).toFixed(2)+'"':'';
   h+='<div class="c'+(c.n?' on':'')+'"'+sty+' title="'+
      esc(DAYS[d]+' '+(i<10?'0':'')+i+':00 UTC  -  '+c.n+' row(s)'+
          (c.n?', worst '+c.s:''))+'"></div>';}}
 return h+'<div class="hx"><span>00</span><span>06</span><span>12</span>'+
   '<span>18</span><span>23</span></div></div>';
}
/* One row per distinct value of `col`, as [value, hits, worst severity].
   HACKTOOL_HITS, SIGMA_MATCHES and YARA_MATCHES are the same shape - a name,
   a severity, and a whole-collection count repeated on every sample row - so
   one reader serves all three rather than three that drift apart.

   The count is taken, not summed: it already covers every reference, and the
   table keeps only a sample of the rows, so summing would report a tool seen
   40 times as seen 480. A table without the column is ranked by how many rows
   it actually carries instead. */
function rank(name,col){
 var t=TB[name];
 if(!t)return [];
 var vi=ci(t,col),ni=ci(t,'count'),si=ci(t,'severity');
 if(vi<0)return [];
 var m={},sev={},out=[],k;
 t.rows.forEach(function(r){
  var v=r[vi];
  if(!v)return;
  if(ni>=0){
   var n=parseInt(r[ni],10);
   if(!(n>0))n=1;
   if(m[v]===undefined||n>m[v])m[v]=n;
  }else{m[v]=(m[v]||0)+1;}
  if(si>=0&&(sev[v]===undefined||sevRank(r[si])<sevRank(sev[v])))sev[v]=r[si];});
 for(k in m)out.push([k,m[k],sev[k]||'INFO']);
 out.sort(function(a,b){
  var d=sevRank(a[2])-sevRank(b[2]);
  return d?d:b[1]-a[1];});
 return out;
}
function toolPairs(){return rank(HT,'tool');}
/* The named-hit grids the overview ranks, beyond the tooling panel that leads
   it. A table that was not built simply has no panel. */
var RANKED=[['SIGMA_MATCHES','rule','Sigma rules fired'],
            ['YARA_MATCHES','rule','YARA rules matched'],
            ['IOC_HITS','indicator','Pivot indicators']];
function tally(list,fn){
 var m={},out=[],k;
 list.forEach(function(x){
  var ks=fn(x);
  if(!ks)return;
  if(!(ks instanceof Array))ks=[ks];
  ks.forEach(function(kk){m[kk]=(m[kk]||0)+1;});});
 for(k in m)out.push([k,m[k]]);
 out.sort(function(a,b){return b[1]-a[1];});
 return out;
}


/* ---------- the calendar ---------- */
/* A month grid rather than a native date input, for one reason: this one can
   shade the days that actually carry evidence. A collection is mostly empty
   days and three loud ones, and "which days is there anything on" is the
   question a reader has before they can pick a window at all - a native
   picker shows a blank month and leaves them guessing.

   The boxes stay typeable. The calendar is the way in; '-24h' is still the
   fastest way to say the last day, and taking that away to force clicking
   would be a worse control, not a better one. */
var CALFOR=null,CALMON=null,CALH=0,CALM=0;
var WD=['Mo','Tu','We','Th','Fr','Sa','Su'];
var MON=['January','February','March','April','May','June','July','August',
         'September','October','November','December'];
function p2(x){return (x<10?'0':'')+x;}
function ymd(y,m,d){return y+'-'+p2(m+1)+'-'+p2(d);}
/* Rows per UTC day, for the shading. Read off the same table the activity
   chart is drawn from, so the calendar and the chart cannot disagree about
   where the evidence is. */
var DAYN=null;
function dayCounts(){
 if(DAYN)return DAYN;
 DAYN={max:0,n:{}};
 var t=vt('timeline')||vt('findings');
 if(!t)return DAYN;
 var tc=tcols(t);
 t.rows.forEach(function(r){
  var sp=rowSpan(tc,r);
  if(!sp)return;
  var d=new Date(sp[0]*1000);
  var k=ymd(d.getUTCFullYear(),d.getUTCMonth(),d.getUTCDate());
  DAYN.n[k]=(DAYN.n[k]||0)+1;
  if(DAYN.n[k]>DAYN.max)DAYN.max=DAYN.n[k];});
 return DAYN;
}
/* The month to open on: the end of the value already in the box, else the
   month the evidence ends in. Never the reader's current month - a
   collection from three years ago would open on an empty grid. */
function calMonthFor(which){
 var v=parseWhen(el(which)?el(which).value:'',which==='t1');
 if(v===null||v===undefined)v=dataMax()||Math.floor(Date.now()/1000);
 var d=new Date(v*1000);
 return Date.UTC(d.getUTCFullYear(),d.getUTCMonth(),1)/1000;
}
function calHtml(){
 var d0=new Date(CALMON*1000),y=d0.getUTCFullYear(),m=d0.getUTCMonth();
 var first=(new Date(Date.UTC(y,m,1)).getUTCDay()+6)%7;   /* Monday-first */
 var days=new Date(Date.UTC(y,m+1,0)).getUTCDate();
 var dc=dayCounts(),i;
 var h='<div class="hd"><button class="nav" data-mv="-1">&lsaquo;</button>'+
   '<b>'+MON[m]+' '+y+'</b>'+
   '<button class="nav" data-mv="1">&rsaquo;</button></div><div class="grid">';
 WD.forEach(function(w){h+='<div class="wd">'+w+'</div>';});
 for(i=0;i<first;i++)h+='<div class="d pad"></div>';
 for(i=1;i<=days;i++){
  var k=ymd(y,m,i),n=dc.n[k]||0;
  /* the day's start and end, to say whether it is inside the window */
  var s0=Date.UTC(y,m,i)/1000,s1=s0+86399;
  var inWin=winOn()&&!(st.t1!==null&&s0>st.t1)&&!(st.t0!==null&&s1<st.t0);
  var edge=winOn()&&((st.t0!==null&&st.t0>=s0&&st.t0<=s1)||
                     (st.t1!==null&&st.t1>=s0&&st.t1<=s1));
  var cls='d'+(n?'':' none')+(inWin?' in':'')+(edge?' edge':'');
  h+='<div class="'+cls+'" data-d="'+k+'" title="'+esc(k+' \u2014 '+
     (n?n.toLocaleString()+' row(s)':'nothing'))+'">'+
     (n?'<div class="lvl" style="opacity:'+
        (0.16+0.5*Math.sqrt(n/(dc.max||1))).toFixed(2)+'"></div>':'')+
     '<span>'+i+'</span></div>';}
 h+='</div><div class="ft"><span class="lb">time</span>'+
    '<select id="calh">';
 for(i=0;i<24;i++)h+='<option value="'+i+'"'+(i===CALH?' selected':'')+'>'+
   p2(i)+'</option>';
 h+='</select><span class="lb">:</span><select id="calm">';
 for(i=0;i<60;i++)h+='<option value="'+i+'"'+(i===CALM?' selected':'')+'>'+
   p2(i)+'</option>';
 h+='</select><span class="lb">UTC</span></div>';
 h+='<div class="pre"><button data-pre="24h">last 24h</button>'+
    '<button data-pre="7d">7d</button><button data-pre="30d">30d</button>'+
    '<button data-pre="all">all</button></div>';
 return h;
}
function calRender(){
 var c=el('cal');
 if(!c)return;
 c.innerHTML=calHtml();
 [].forEach.call(c.querySelectorAll('[data-mv]'),function(b){
  b.onclick=function(){
   var d=new Date(CALMON*1000);
   CALMON=Date.UTC(d.getUTCFullYear(),d.getUTCMonth()+(+b.getAttribute('data-mv')),1)/1000;
   calRender();};});
 [].forEach.call(c.querySelectorAll('.d[data-d]'),function(x){
  x.onclick=function(){calPick(x.getAttribute('data-d'));};});
 var hh=el('calh'),mm=el('calm');
 /* changing the time re-applies it to the day already chosen, so the boxes
    never disagree with the selects sitting above them */
 if(hh)hh.onchange=function(){CALH=+hh.value;calRetime();};
 if(mm)mm.onchange=function(){CALM=+mm.value;calRetime();};
 [].forEach.call(c.querySelectorAll('[data-pre]'),function(b){
  b.onclick=function(){calPreset(b.getAttribute('data-pre'));};});
}
function calOpen(which){
 var i=el(which),c=el('cal');
 if(!i||!c)return;
 CALFOR=which;
 CALMON=calMonthFor(which);
 /* a 'to' bound defaults to the end of its day, a 'from' bound to the start:
    picking one day at each end should mean that whole day */
 var cur=/(\\d\\d):(\\d\\d)/.exec(i.value||'');
 CALH=cur?+cur[1]:(which==='t1'?23:0);
 CALM=cur?+cur[2]:(which==='t1'?59:0);
 calRender();
 var r=i.getBoundingClientRect();
 c.style.left=Math.max(6,Math.min(r.left,
   (window.innerWidth||900)-252))+'px';
 c.style.top=(r.bottom+6)+'px';
 c.classList.add('open');
}
function calClose(){
 var c=el('cal');
 if(c)c.classList.remove('open');
 CALFOR=null;
}
function calWrite(text){
 var i=el(CALFOR);
 if(!i)return;
 i.value=text;
 readWin();
}
function calPick(k){
 if(!CALFOR)return;
 calWrite(k+' '+p2(CALH)+':'+p2(CALM));
 calRender();          /* repaint so the new window shows in the grid */
}
function calRetime(){
 var i=el(CALFOR);
 if(!i)return;
 var m=/^(\\d{4}-\\d\\d-\\d\\d)/.exec(i.value||'');
 if(m)calWrite(m[1]+' '+p2(CALH)+':'+p2(CALM));
}
/* The presets set both ends at once, so they close the popover: there is
   nothing left to pick. */
function calPreset(kind){
 if(kind==='all'){setWin(null,null);calClose();return;}
 var end=dataMax();
 if(!end){calClose();return;}
 var back={'24h':86400,'7d':604800,'30d':2592000}[kind];
 setWin(end-back,end);
 calClose();
}


/* ---------- overview ---------- */
function viewOverview(){
 var f=fc(),fs=frows(),tl=vt('timeline'),tp=toolPairs();
 var techs=f?tally(fs,function(r){return techsOf(r[f.mitre]);}):[];
 var h='<h2>Overview</h2>'+(winOn()?'<div class="pills"><span class="pill" '+
   'data-winclear="1">time window: '+esc(fmtWin())+' &times;</span></div>':'')+
   '<div class="cards">';
 if(f)SEV.forEach(function(s){
  var n=fs.filter(function(r){return r[f.severity]===s;}).length;
  h+='<div class="card" data-sev="'+s+'" style="border-top-color:var(--'+s+')">'+
     '<b style="color:var(--'+s+')">'+n+'</b><span>'+s+'</span></div>';});
 if(tp.length)h+='<div class="card" data-tbl="'+HT+
    '" style="border-top-color:var(--CRITICAL)"><b>'+tp.length.toLocaleString()+
    '</b><span>OFFENSIVE TOOLS</span></div>';
 if(techs.length)h+='<div class="card" data-go="attack" '+
    'style="border-top-color:var(--accent)"><b>'+techs.length.toLocaleString()+
    '</b><span>TECHNIQUES</span></div>';
 if(tl)h+='<div class="card" data-go="timeline" style="border-top-color:var(--gold)">'+
    '<b>'+tl.row_count.toLocaleString()+'</b><span>TIMELINE EVENTS</span></div>';
 h+='</div>';

 /* The tooling ranking leads, because it is the one panel that names a thing
    rather than counting one: 'nmap, linpeas, chisel' is a sentence about the
    host, where a severity total is a sentence about the report. */
 if(tp.length)h+='<h3>Offensive tooling <span class="count">&mdash; click a '+
    'tool for its hits</span></h3>'+barList(tp.slice(0,12),'tool');

 /* Two clocks side by side. The left is what the collection recorded, the
    right is what the analysis raised out of it - a spike of log volume with
    no findings under it reads nothing like the reverse, and neither shape is
    visible in the other chart. */
 h+='<div class="grid2"><div><h3>Activity <span class="count">&mdash; click a '+
    'column to narrow the time window, shift-click to extend</span></h3>'+
    (tl?histo(tl.rows,ci(tl,'timestamp_utc'),ci(tl,'severity'),60,88,true).html
       :'<div class="empty">no timeline</div>')+'</div>';
 h+='<div><h3>Findings over time</h3>'+
    (f&&f.first_utc>=0&&fs.length
      ?histo(fs,f.first_utc,f.severity,60,88,false).html
      :'<div class="empty">no dated findings</div>')+'</div></div>';

 /* The same rows on a week's clock face. The hour profile beside it answers
    'what is the daily rhythm'; this answers 'which day and hour exactly',
    which is the question asked of an out-of-hours login. */
 if(tl)h+='<h3>When it happened <span class="count">&mdash; day of week by '+
    'hour, UTC</span></h3>'+heat(tl.rows,ci(tl,'timestamp_utc'),ci(tl,'severity'));

 h+='<div class="grid2"><div><h3>Activity by hour (UTC)</h3>'+
    (tl?hourly(tl.rows,ci(tl,'timestamp_utc'),ci(tl,'severity'),88)
       :'<div class="empty">no timeline</div>')+'</div>';
 h+='<div><h3>Collection</h3><table class="meta">';
 D.meta.forEach(function(kv){
  h+='<tr><td>'+esc(kv[0])+'</td><td>'+esc(kv[1])+'</td></tr>';});
 h+='</table></div></div>';

 h+='<div class="grid2"><div><h3>Categories</h3>'+
    barList(tally(fs,function(r){return r[f.category];}).slice(0,14),'cat')+'</div>';
 h+='<div><h3>Techniques</h3>'+
    barList(techs.slice(0,14),'tech',techLabel)+'</div></div>';

 h+='<div class="grid2"><div><h3>Tactics</h3>'+
    barList(tally(fs,function(r){
     return uniq(techsOf(r[f.mitre]).map(tacticOf));}).slice(0,14),'tac')+'</div>';
 h+='<div><h3>Loudest artifacts</h3>'+
    barList(tally(fs,function(r){return r[f.artifact];}).slice(0,14),'')+
    '</div></div>';

 /* What the rule engines and the pivot actually fired on, each ranked out of
    its own grid and each bar a click into that grid, filtered to the row it
    names. A panel appears only when its table was built. */
 var last=[];
 RANKED.forEach(function(p){
  var pr=rank(p[0],p[1]);
  if(pr.length)last.push('<div><h3>'+esc(p[2])+'</h3>'+
   barList(pr.slice(0,12),'tbl:'+p[0])+'</div>');});
 /* Where the evidence actually is. The nav carries a row count per table, but
    sorted by category rather than by size - and 'which of these 88 grids is
    worth opening' is answered by the size. */
 var big=IDX.filter(function(t){return !isView(t)&&t.rows;})
    .map(function(t){return [t.name,t.rows];})
    .sort(function(a,b){return b[1]-a[1];}).slice(0,12);
 if(big.length)last.push('<div><h3>Largest tables</h3>'+
   barList(big,'open')+'</div>');
 if(last.length)h+='<div class="grid2">'+last.join('')+'</div>';
 return h;
}
function techLabel(t){
 var f=fc(),nm='';
 if(f)f.t.rows.some(function(r){
  if(techsOf(r[f.mitre]).indexOf(t)>=0){nm=techName(r[f.mitre],t);return !!nm;}
  return false;});
 return nm?t+'  '+nm:t;
}

/* ---------- attack ---------- */
function viewAttack(){
 var f=fc(),fs=frows(),by={};
 fs.forEach(function(r){
  techsOf(r[f.mitre]).forEach(function(t){
   var tac=tacticOf(t);
   if(!by[tac])by[tac]={};
   if(!by[tac][t])by[tac][t]={n:0,sev:'INFO',nm:techName(r[f.mitre],t)};
   by[tac][t].n++;
   if(!by[tac][t].nm)by[tac][t].nm=techName(r[f.mitre],t);
   if(sevRank(r[f.severity])<sevRank(by[tac][t].sev))by[tac][t].sev=r[f.severity];});});
 var order=D.order.filter(function(t){return by[t];});
 if(!order.length)return '<h2>ATT&amp;CK</h2><div class="empty">'+
   'no findings carry a technique at this filter</div>';
 var h='<h2>ATT&amp;CK <span class="count">&mdash; click a technique to filter '+
   'the findings</span></h2><div class="matrix">';
 order.forEach(function(tac){
  var tsl=[],t;
  for(t in by[tac])tsl.push(t);
  tsl.sort(function(a,b){
   var d=sevRank(by[tac][a].sev)-sevRank(by[tac][b].sev);
   return d?d:by[tac][b].n-by[tac][a].n;});
  h+='<div class="tac"><div class="h"><b>'+esc(tac)+'</b>'+tsl.length+
     ' technique(s)</div>';
  tsl.forEach(function(t){
   var c=by[tac][t];
   h+='<div class="cell" data-tech="'+esc(t)+'" style="border-left-color:var(--'+
      c.sev+')"><div class="id">'+esc(t)+'<span class="n">'+c.n+'</span></div>'+
      (c.nm?'<div class="nm">'+esc(c.nm)+'</div>':'')+'</div>';});
  h+='</div>';});
 return h+'</div>';
}

/* ---------- what the three grid views add above their table ---------- */
/* The console half of a view: everything that is not the grid itself. The
   grid underneath is the artifact table, rendered by the same code that
   renders every other table, so sorting and per-column filters come for
   free rather than being written twice. */
function viewHead(){
 var h='';
 if(st.view==='findings'){
  h+='<div class="pills">';
  if(st.cat)h+='<span class="pill" data-clear="cat">category: '+esc(st.cat)+
    ' &times;</span>';
  if(st.tech)h+='<span class="pill" data-clear="tech">'+esc(st.tech)+
    ' &times;</span>';
  h+='</div>'+detailHtml();
 }else if(st.view==='timeline'){
  var t=TB[st.table];
  /* Drawn from what the chips, the row filter and the column filters left,
     but never from the window: picking a spike must not hide the shape the
     spike sits in. */
  h+=histo(tMatching(t,true),ci(t,'timestamp_utc'),ci(t,'severity'),80,132,true).html;
 }
 if(winOn())h+='<div class="pills"><span class="pill" data-winclear="1">'+
   'time window: '+esc(fmtWin())+' &times;</span></div>';
 return h;
}

/* The finding under the cursor, read out of the row itself - the grid holds
   every column the detail pane needs, evidence included. */
function detailHtml(){
 var f=fc(),r=st.sel;
 if(!f||!r)return '';
 var h='<div class="detail" id="det"><span class="x" data-clear="sel">&times;</span>'+
   '<h4><span class="tag" style="background:var(--'+r[f.severity]+
   ');color:#0f1419;padding:1px 6px;border-radius:3px;font-size:10px;'+
   'margin-right:7px">'+esc(r[f.severity])+'</span>'+esc(r[f.title])+'</h4>';
 if(f.detail>=0&&r[f.detail])h+='<div class="d">'+esc(r[f.detail])+'</div>';
 h+='<div class="kv"><span>category</span><div>'+esc(r[f.category])+'</div>';
 if(r[f.artifact])h+='<span>artifact</span><div><code>'+esc(r[f.artifact])+
   '</code></div>';
 var seen=[r[f.first_utc],r[f.last_utc]].filter(Boolean);
 if(seen.length)h+='<span>seen</span><div>'+esc(seen.join(' .. '))+' UTC</div>';
 h+='<span>occurrences</span><div>'+esc(r[f.count])+'</div>';
 var tl=techsOf(r[f.mitre]);
 if(tl.length){
  h+='<span>ATT&amp;CK</span><div>';
  tl.forEach(function(t){
   var nm=techName(r[f.mitre],t);
   h+='<span class="pill" data-tech="'+esc(t)+'">'+esc(t)+(nm?' '+esc(nm):'')+
      '</span>';});
  h+='</div>';}
 h+='</div>';
 if(f.evidence>=0&&r[f.evidence])h+='<pre>'+esc(r[f.evidence])+'</pre>';
 return h+'</div>';
}

/* ---------- nav ---------- */
/* Views first, then the pinned offensive-tool grids, then every remaining
   table under its category. The analysis tables are not listed twice - they
   are the views above. */
function navRow(t){
 return '<a class="tbl" data-t="'+esc(t.name)+'" title="'+esc(t.title)+'"><span>'+
   esc(t.name)+'</span><span class="n">'+t.rows.toLocaleString()+'</span></a>';
}
function buildNav(){
 var h='';
 if(fc()||vt('timeline')){
  VIEWS.forEach(function(v){
   var t=vt(v[0]),n=t?'<span class="n">'+t.row_count.toLocaleString()+'</span>':'';
   h+='<a data-v="'+v[0]+'">'+v[1]+n+'</a>';});}
 var rest=IDX.filter(function(t){return !isView(t);});
 /* PIN order, not index order: HACKTOOL_HITS is the list of references and
    HACKTOOL_VARIANTS is that list rolled up, so the roll-up reads as a
    summary of the row above it rather than as a separate table. */
 var pin=[];
 PIN.forEach(function(nm){
  rest.forEach(function(t){if(t.name===nm)pin.push(t);});});
 rest=rest.filter(function(t){return PIN.indexOf(t.name)<0;});
 if(pin.length){
  h+='<div class="sec"></div><div class="cat">Offensive tooling</div>';
  pin.forEach(function(t){h+=navRow(t);});}
 if(rest.length){
  var byCat={},order=[];
  rest.forEach(function(t){
   if(!byCat[t.category]){byCat[t.category]=[];order.push(t.category);}
   byCat[t.category].push(t);});
  h+='<div class="sec"></div>';
  order.forEach(function(c){
   h+='<div class="cat">'+esc(c||'Other')+'</div>';
   byCat[c].forEach(function(t){h+=navRow(t);});});}
 el('nav').innerHTML=h;
 [].forEach.call(document.querySelectorAll('nav a'),function(a){
  a.onclick=function(){
   var t=a.getAttribute('data-t');
   setView(t?'table':a.getAttribute('data-v'),t);};});
}

/* ---------- render ---------- */
/* Search every table at once.
   The per-table box answers "where in this grid", which is the question you
   have once you already know which grid. The question an examination starts
   from is the other one - this address, this hash, this filename, anywhere in
   the evidence - and answering it by opening forty tables in turn is how an
   indicator gets missed in the one nobody thought to open.
   Every row of every table is scanned, so this is the whole export and not a
   sample of it. That costs a pass over the payload, which is why it runs on a
   debounce rather than on every keystroke. */
function searchAll(q){
 q=String(q||'').toLowerCase();
 var out=[];
 if(q.length<2)return out;
 for(var i=0;i<IDX.length;i++){
  var name=IDX[i].name,t=TB[name];
  if(!t||!t.rows)continue;
  var rows=t.rows,n=0,sample=[];
  for(var r=0;r<rows.length;r++){
   var row=rows[r],hit=false;
   for(var c=0;c<row.length;c++){
    var v=row[c];
    if(v&&String(v).toLowerCase().indexOf(q)>=0){hit=true;break;}
   }
   if(hit){n++;if(sample.length<3)sample.push(row);}
  }
  if(n)out.push({name:name,title:t.title,count:n,sample:sample,cols:t.columns,
                 capped:t.row_count>rows.length,total:t.row_count,
                 rows:rows.length});
 }
 out.sort(function(a,b){return b.count-a.count;});
 return out;
}
function viewSearch(){
 var q=st.gq||'';
 var h='<h1>Search all tables</h1>';
 h+='<div class="controls"><input type="search" id="gq" placeholder="an address, '+
    'a hash, a filename, a username - anywhere in the evidence..." value="'+
    esc(q)+'"></div>';
 if(q.length<2){
  h+='<p class="desc">Type at least two characters. Every row of every table '+
     'is searched, so this covers the whole export rather than the table you '+
     'happen to be looking at.</p>';
  return h;
 }
 var res=searchAll(q);
 if(!res.length){
  h+='<div class="empty">Nothing in any table matches '+esc(q)+'.</div>';
  return h;
 }
 var total=0;res.forEach(function(x){total+=x.count;});
 h+='<p class="desc">'+total.toLocaleString()+' matching row(s) in '+
    res.length+' table(s). Click a table to open it with this filter applied.</p>';
 res.forEach(function(x){
  h+='<div class="card2"><a class="gs" data-t="'+esc(x.name)+'"><b>'+esc(x.name)+
     '</b> <span class="badge">'+x.count.toLocaleString()+'</span></a> '+
     '<span class="desc">'+esc(x.title||'')+
     (x.capped?' - the page holds '+x.rows.toLocaleString()+' of '+
      x.total.toLocaleString()+' rows, so this searched those':'')+'</span>';
  h+='<table class="mini"><tr>';
  x.cols.forEach(function(c){h+='<th>'+esc(c)+'</th>';});
  h+='</tr>';
  x.sample.forEach(function(r){
   h+='<tr>';
   for(var i=0;i<x.cols.length;i++){h+='<td>'+esc(r[i]==null?'':r[i])+'</td>';}
   h+='</tr>';});
  h+='</table></div>';});
 return h;
}
/* Drawn only once the rows the view reads are decoded. Everything below
   this point may assume TB[name].rows is an array. */
function draw(){
 /* Every view except the overview and the matrix is a table, and a table
    renders itself: it owns its sort, its column filters and its caret, none
    of which survive being rebuilt from a string. */
 if(st.view==='table'||vt(st.view)){tRender();markNav();return;}
 el('main').innerHTML=st.view==='search'?viewSearch()
  :st.view==='attack'?viewAttack():viewOverview();
 wire();
 markNav();
}
function render(){
 var want=needs(),cold=want.filter(function(n){
  return TB[n]&&TB[n].rows===undefined&&PACK[n];});
 /* Only says so when there is actually a wait. Decoding one small grid is
    faster than the message would be readable. */
 if(cold.length)el('main').innerHTML='<div class="empty">Decoding '+
  cold.length+' table'+(cold.length>1?'s':'')+'...</div>';
 ensure(want).then(draw);
}
/* Open an artifact grid with its row filter already typed in. A tool bar in
   the overview is a question about one tool, and landing on the unfiltered
   table leaves the reader to retype the name they just clicked. */
function goTable(name,q){
 if(!TB[name])return;
 st.table=name;sortCol=-1;colFilters=[];st.tq=q||'';
 st.view='table';
 location.hash='t/'+name;
 render();
}
var gqTimer=null;
function wire(){
 wireHisto();
 wireWin();
 var gq=el('gq');
 if(gq){
  gq.oninput=function(){
   /* debounced: this reads every row of every table, and doing that on each
      keystroke of a 40 MB export makes the box feel broken */
   if(gqTimer)clearTimeout(gqTimer);
   var v=gq.value;
   gqTimer=setTimeout(function(){
    st.gq=v;
    ensure(needs()).then(function(){
     el('main').innerHTML=viewSearch();
     wire();
     var b=el('gq');
     if(b){b.focus();b.setSelectionRange(b.value.length,b.value.length);}
    });
   },250);};
  [].forEach.call(document.querySelectorAll('a.gs'),function(a){
   a.onclick=function(){goTable(a.getAttribute('data-t'),st.gq||'');};});
 }
 [].forEach.call(document.querySelectorAll('[data-tech]'),function(x){
  x.onclick=function(){st.tech=x.getAttribute('data-tech');setView('findings');};});
 [].forEach.call(document.querySelectorAll('.card[data-sev]'),function(cd){
  cd.onclick=function(){
   var s=cd.getAttribute('data-sev');
   SEV.forEach(function(x){st.sev[x]=(x===s);});
   chips();setView('findings');};});
 [].forEach.call(document.querySelectorAll('.card[data-go]'),function(cd){
  cd.onclick=function(){setView(cd.getAttribute('data-go'));};});
 [].forEach.call(document.querySelectorAll('.card[data-tbl]'),function(cd){
  cd.onclick=function(){goTable(cd.getAttribute('data-tbl'),'');};});
 [].forEach.call(document.querySelectorAll('.bar[data-act]'),function(b){
  b.onclick=function(){
   var a=b.getAttribute('data-act'),k=b.getAttribute('data-k');
   if(a==='cat'){st.cat=k;setView('findings');}
   else if(a==='tech'){st.tech=k;setView('findings');}
   /* A tactic is not a findings filter - the matrix is the view that draws
      one, so the click lands there rather than on a filter that cannot be
      expressed. */
   else if(a==='tac'){setView('attack');}
   else if(a==='tool'){goTable(HT,k);}
   /* 'tbl:NAME' carries its own destination, so one handler serves every
      ranked panel and a new panel needs no new branch here. */
   else if(a.indexOf('tbl:')===0){goTable(a.slice(4),k);}
   else if(a==='open'){goTable(k,'');}};});
}
function start(){
 /* Wired once and never rebuilt: these live in the header, outside main, so
    they keep their text and their caret across every render - the same reason
    the per-column filter inputs are left alone by tRefresh. */
 ['t0','t1'].forEach(function(id){
  var i=el(id);
  if(!i)return;
  i.oninput=function(){readWin();if(CALFOR===id)calRender();};
  i.onfocus=function(){calOpen(id);};
  i.onclick=function(ev){(ev||window.event).stopPropagation();calOpen(id);};});
 var tc=el('tclr');
 if(tc)tc.onclick=function(){setWin(null,null);calClose();};
 /* The popover eats its own clicks, so the handler below only ever sees the
    ones that really are outside it.

    This cannot be done by walking up from ev.target instead: every control in
    here re-renders the grid, which replaces the popover's innerHTML and
    detaches the very node that was clicked. The walk then finds no parent, the
    click reads as 'outside', and stepping to the previous month closed the
    calendar. The event path is fixed when the event is dispatched, so this
    listener still runs on a node that has since been thrown away. */
 var cw=el('cal');
 if(cw)cw.onclick=function(ev){(ev||window.event).stopPropagation();};
 document.addEventListener('click',function(){
  var c=el('cal');
  if(c&&c.classList.contains('open'))calClose();});
 /* The severity chips count FINDINGS rows and the first view reads them,
    so the page waits for that one decode before it draws anything. It is
    the only wait the console makes on open: every other table is decoded
    when it is opened. */
 el('main').innerHTML='<div class="empty">Opening the export...</div>';
 ensure(needs()).then(function(){
  chips();
  buildNav();
  var v=(location.hash||'').replace('#','');
  if(v.indexOf('t/')===0&&TB[v.slice(2)])setView('table',v.slice(2));
  else if(['overview','findings','attack','timeline'].indexOf(v)>=0&&
          (fc()||vt('timeline')))setView(v);
  else if(fc()||vt('timeline'))setView('overview');
  else if(IDX.length)setView('table',IDX[0].name);
 });
 document.onkeydown=function(e){
  if(e.target.tagName==='INPUT'||e.target.tagName==='SELECT')return;
  var k=e.key;
  if(k==='/'){var q=el('q');if(q){q.focus();e.preventDefault();}}
  if(k==='t'){var tb=el('t0');if(tb){tb.focus();calOpen('t0');e.preventDefault();}}
  if(k==='Escape'&&CALFOR)calClose();
  if(k>='1'&&k<='4'&&fc())setView(['overview','findings','attack',
   'timeline'][+k-1]);
  /* j/k walk the rows of whichever grid is open, the way the console report
     is read - and in the findings view that moves the detail pane with it. */
  if(k==='j'||k==='k'){
   if(!TLAST.length)return;
   var i=TLAST.indexOf(st.sel);
   i=Math.max(0,Math.min(TLAST.length-1,i<0?0:i+(k==='j'?1:-1)));
   st.sel=TLAST[i];
   if(st.view==='findings'){render();}
   var sel=document.querySelector('tbody tr.sel');
   if(sel&&sel.scrollIntoView)sel.scrollIntoView({block:'nearest'});}};
}
/* ---------- tables ---------- */
var sortCol=-1,sortAsc=true;
var colFilters=[],lay=null;   /* per-column filter text; measured column tLayout */



/* Per-column width from the rows on screen, not from the widest value in the
   table: sizing to the maximum lets a single long cell decide the tLayout, and
   every other column ends up too narrow to read. The 90th percentile fits the
   rows being scanned and leaves the outliers to wrap or scroll in place.
   Recomputed per tRender so it follows the filter - narrowing to one noisy
   process should retighten the columns around what is left. */
function tLayout(t,rows,cap){
 var n=t.columns.length,out=[],step=Math.max(1,Math.floor(cap/200));
 for(var j=0;j<n;j++){
  var lens=[],num=(rows.length>0),seen=0;
  for(var i=0;i<cap;i+=step){
   var v=rows[i][j];if(v===undefined||v===null||v==='')continue;
   v=String(v);seen++;
   if(num&&!/^-?[\\d.]+$/.test(v))num=false;
   var parts=v.split('\\n'),m=0;
   for(var k=0;k<parts.length;k++)if(parts[k].length>m)m=parts[k].length;
   lens.push(m);
  }
  lens.sort(function(a,b){return a-b;});
  var p90=lens.length?lens[Math.min(lens.length-1,Math.floor(lens.length*0.9))]:0;
  var chars=Math.max(t.columns[j].length+2,p90);
  /* Short columns keep their content on one line; long ones wrap. The
     threshold sits above a UTC timestamp (19 chars) on purpose - wrapping
     '2026-06-11 12:24:57' onto two lines doubles the height of every row in
     the table for no gain. */
  var nw=(p90<=28&&!num)||(num&&seen);
  var px=Math.round(chars*7.2)+18;
  out.push({w:Math.max(64,Math.min(nw?300:460,px)),num:(num&&seen>0),nw:nw});
 }
 return out;
}
function tSortRows(rows){
 return rows.slice().sort(function(a,b){
  var x=a[sortCol]||'',y=b[sortCol]||'';
  var nx=parseFloat(x),ny=parseFloat(y);
  var c=(!isNaN(nx)&&!isNaN(ny)&&/^-?[\\d.]+$/.test(x)&&/^-?[\\d.]+$/.test(y))
       ?nx-ny:String(x).localeCompare(String(y));
  return sortAsc?c:-c;});
}
/* The global box searches the whole row; a per-column box searches only its
   own column. They combine with AND, which is what makes them worth having
   separately - 'sshd' anywhere plus user=root is a different question from
   either on its own. */
/* `raw` skips nothing any more except the caller's own reason for asking:
   the timeline chart passes it so that it draws the shape the window was
   picked out of rather than only the window. */
function tMatching(t,raw){
 var q=(st.tq||'').toLowerCase();
 var rows=t.rows;
 if(q){rows=rows.filter(function(r){return r.join(' ').toLowerCase().indexOf(q)>=0;});}
 var act=[];
 for(var i=0;i<colFilters.length;i++){
  if(colFilters[i]){act.push([i,colFilters[i].toLowerCase()]);}}
 if(act.length){rows=rows.filter(function(r){
  for(var k=0;k<act.length;k++){
   var v=r[act[k][0]];v=(v===undefined||v===null)?'':String(v);
   if(v.toLowerCase().indexOf(act[k][1])<0){return false;}}
  return true;});}
 /* The header chips, the category / technique pills and the timeline bucket
    are filters too, and they have to bite here rather than in a second pass:
    the row count, the chart and the grid all read this one list, and a view
    whose chips disagree with its own table is worse than no chips at all.
    Only the three console tables answer to them - an artifact grid that
    happens to carry a severity column is not the findings list. */
 /* Before the view-only filters, and outside the isView() guard: the window
    is the one filter that applies to an artifact grid as much as to the
    findings list. */
 if(winOn()&&!raw){
  var tc=tcols(t);
  if(tc.any)rows=rows.filter(function(r){return inWindow(tc,r);});}
 var v=isView(t);
 if(v){
  var si=t.columns.indexOf('severity');
  if(si>=0)rows=rows.filter(function(r){return st.sev[r[si]]!==false;});
  if(v==='findings'){
   var f=fc();
   if(st.cat)rows=rows.filter(function(r){return r[f.category]===st.cat;});
   if(st.tech)rows=rows.filter(function(r){
    return techsOf(r[f.mitre]).indexOf(st.tech)>=0;});}
  }
 if(sortCol>=0){rows=tSortRows(rows);}
 TLAST=rows;
 return rows;
}
var TLAST=[];   /* the rows on screen, in the order they are on screen */
/* Excel offers a tick-list of a column's distinct values; the same idea here
   is a <datalist>, so a low-cardinality column (level, user, process, status)
   suggests what is actually in it instead of making you guess. Columns whose
   values are long or nearly unique get no list - a dropdown of 60 different
   log messages is noise. */
function tOptions(t,j){
 var seen={},n=0,step=Math.max(1,Math.floor(t.rows.length/4000));
 for(var i=0;i<t.rows.length;i+=step){
  var v=t.rows[i][j];v=(v===undefined||v===null)?'':String(v);
  if(!v){continue;}
  if(v.length>48){return null;}
  if(!seen[v]){seen[v]=1;n++;if(n>60){return null;}}}
 return n>1?Object.keys(seen).sort():null;
}
function tBodyHtml(t,rows,cap){
 var sevIdx=t.columns.indexOf('severity'),h='';
 for(var i=0;i<cap;i++){
  var r=rows[i];h+='<tr data-r="'+i+'"'+(r===st.sel?' class="sel"':'')+'>';
  for(var j=0;j<t.columns.length;j++){
   var v=r[j]===undefined?'':r[j];
   var cls=(sevIdx===j)?'sev-'+esc(v):(lay[j].num?'num':'');
   if(lay[j].nw){cls+=(cls?' ':'')+'nw';}
   h+='<td'+(cls?' class="'+cls+'"':'')+'><div class="c">'+esc(v)+'</div></td>';}
  h+='</tr>';}
 return h;
}
/* Only the tbody and the counters are rebuilt, never the filter inputs:
   replacing an input while it has focus loses the caret, which makes it
   impossible to type more than one character into a filter. */
/* Why a grid is empty, when the answer is 'the header chips', not 'the data'.
   A table can legitimately hold no rows at one severity - isolate CRITICAL on
   a collection whose criticals are all undated and the timeline has nothing
   to show - and 'No rows match.' reads as a broken page rather than as an
   answer. Say which severities are on, what the table does hold, and offer
   the way out. */
function emptyNote(t){
 var plain='No rows match.';
 if(!t)return plain;
 var si=t.columns.indexOf('severity');
 if(si<0||!isView(t))return plain;
 var on=SEV.filter(function(s){return st.sev[s];});
 if(!on.length)return 'Every severity is switched off in the header.'+
   ' <span class="pill" id="allsev">show all &times;</span>';
 if(on.length===SEV.length)return plain;
 var have={};
 t.rows.forEach(function(r){have[r[si]]=(have[r[si]]||0)+1;});
 if(on.some(function(s){return have[s];}))return plain;
 return 'No '+on.join(' / ')+' rows in '+esc(t.name)+'. It holds '+
   t.row_count.toLocaleString()+' row(s) at other severities. '+
   '<span class="pill" id="allsev">show all severities &times;</span>';
}
function tRefresh(){
 var t=TB[st.table];if(!t){return;}
 var rows=tMatching(t);
 var cap=rows.length>t.cap?t.cap:rows.length;
 var tb=document.getElementById('tb');
 if(tb){tb.innerHTML=tBodyHtml(t,rows,cap);wireRows();}
 var mn=document.getElementById('matchn');
 if(mn){mn.textContent=rows.length.toLocaleString()+' matching';}
 var note=document.getElementById('note');
 if(note){note.innerHTML=rows.length>cap?'Showing first '+cap.toLocaleString()+
  ' of '+rows.length.toLocaleString()+' matching rows. Narrow the filter, or use'+
  ' the CSV / JSON export for everything.':'';}
 var none=document.getElementById('none');
 if(none){none.style.display=rows.length?'none':'block';
  if(!rows.length){none.innerHTML=emptyNote(t);wireEmpty();}}
 /* The chart follows the filter, but the box being typed into must not be
    rebuilt - so the head is replaced and re-wired while the input above it
    is left exactly where it is, caret included. */
 var vh=document.getElementById('vhead');
 if(vh){vh.innerHTML=viewHead();wireHead();}
 [].forEach.call(document.querySelectorAll('tr.f input'),function(inp){
  inp.classList.toggle('on',!!inp.value);});
}
function tRender(){
 var t=TB[st.table];if(!t){return;}
 var rows=tMatching(t);
 var cap=rows.length>t.cap?t.cap:rows.length;
 var h='<h2>'+esc(t.title)+' <span class="badge">'+t.name+'</span></h2>';
 h+='<p class="desc">'+esc(t.description||'');
 if(t.sources&&t.sources.length){h+='<br>sources: '+esc(t.sources.join(', '));}
 h+='</p>';
 h+='<div class="controls"><input type="search" id="q" placeholder="filter rows '+
    'in this table..." value="'+esc(st.tq||'')+'"><span class="badge">'+t.row_count.toLocaleString()+
    ' rows total</span><span class="badge" id="matchn">'+rows.length.toLocaleString()+
    ' matching</span><button class="clr" id="clr">clear filters</button>'+
    winBadge(t);
 if(t.no_gzip){h+='<span class="badge warn">this browser has no '+
   'DecompressionStream, so the packed tables cannot be read here \\u2014 '+
   'use the CSV / JSON export, or a current browser</span>';}
 else if(t.decode_error){h+='<span class="badge warn">these rows would not '+
   'decode: '+esc(t.decode_error)+'</span>';}
 else if(t.row_count>t.rows.length){h+='<span class="badge warn">HTML capped at '+
   t.rows.length.toLocaleString()+' \\u2014 full data in the CSV / JSON export</span>';}
 h+='</div>';
 h+='<div id="vhead">'+viewHead()+'</div>';
 /* the layout is measured once per table, not per keystroke - columns that
    resize while you are typing into them are worse than columns that do not */
 lay=tLayout(t,rows.length?rows:t.rows,Math.max(cap,1));
 /* table-layout:fixed only honours the <colgroup> if the table itself has a
    width. Left to 'auto' the browser falls back to shrink-to-fit and sizes
    column 1 from its content - which is how a table of one long field and
    one short one ended up 3567px wide beside a 58px column. Sum the columns
    and say so. */
 var total=0,elastic=-1,widest=0;
 lay.forEach(function(L,i){total+=L.w;
  /* only a wrapping column is a candidate: extra width buys it another line
     of visible text, whereas a one-line column just gains blank space */
  if(!L.num&&!L.nw&&L.w>widest){widest=L.w;elastic=i;}});
 var avail=Math.max(320,(document.getElementById('main').clientWidth||0)-38);
 var stretch=total<avail;
 /* Hand the slack to the widest wrapping column rather than letting fixed
    layout spread it proportionally - a 297px 'seen_in_count' is padding, the
    same pixels on 'seen_in' are another line of the value worth reading. With
    no wrapping column to give it to (a table of short fields), fall back to
    proportional so the table still fills the pane instead of stretching one
    column to 1000px of whitespace. */
 h+='<table class="tbl" style="width:'+(stretch?avail:total)+'px"><colgroup>';
 lay.forEach(function(L,i){
  h+=(stretch&&i===elastic)?'<col>':'<col style="width:'+L.w+'px">';});
 h+='</colgroup><thead><tr id="hdr">';
 t.columns.forEach(function(c,i){
  var mark=sortCol===i?(sortAsc?' \\u25b2':' \\u25bc'):'';
  h+='<th data-i="'+i+'" title="'+esc(c)+' \\u2014 click to sort">'+
     '<span class="lbl">'+esc(c)+mark+'</span></th>';});
 h+='</tr><tr class="f" id="frow">';
 var lists='';
 t.columns.forEach(function(c,i){
  var opts=tOptions(t,i),lid='';
  if(opts){lid='dl_'+i;
   lists+='<datalist id="'+lid+'">';
   opts.forEach(function(o){lists+='<option value="'+esc(o).replace(/"/g,'&quot;')+'">';});
   lists+='</datalist>';}
  h+='<th><input data-i="'+i+'" placeholder="filter '+esc(c)+'"'+
     (lid?' list="'+lid+'"':'')+' value="'+esc(colFilters[i]||'').replace(/"/g,'&quot;')+
     '"></th>';});
 h+='</tr></thead><tbody id="tb">'+tBodyHtml(t,rows,cap)+'</tbody></table>'+lists;
 h+='<div class="empty" id="none"'+(rows.length?' style="display:none"':'')+
    '>'+(rows.length?'No rows match.':emptyNote(t))+'</div>';
 h+='<p class="desc" id="note">'+(rows.length>cap?'Showing first '+cap.toLocaleString()+
  ' of '+rows.length.toLocaleString()+' matching rows. Narrow the filter, or use'+
  ' the CSV / JSON export for everything.':'')+'</p>';
 document.getElementById('main').innerHTML=h;
 tWire();
 wireEmpty();
 wireWin();
}
/* A histogram column is a time range. Clicking one narrows the window to it;
   shift-clicking extends the window to cover both ends, which is how a span
   wider than one bucket is picked without a drag. Clicking the lit column
   again lets go. */
function wireHisto(){
 [].forEach.call(document.querySelectorAll('.histo.click .col'),function(c){
  c.onclick=function(ev){
   ev=ev||window.event;
   var b=HB[+c.getAttribute('data-b')];
   if(!b)return;
   /* the bucket's own end is the next bucket's start, so a hair is taken off
      it - otherwise a row landing exactly on the boundary is in both */
   var lo=b.t0,hi=b.t1-0.001;
   if(ev&&ev.shiftKey&&winOn()){
    if(st.t0!==null&&st.t0<lo)lo=st.t0;
    if(st.t1!==null&&st.t1>hi)hi=st.t1;
   }else if(st.t0===lo&&st.t1===hi){lo=null;hi=null;}
   setWin(lo,hi);};});
}
/* Every 'clear the window' control, wherever it was drawn. */
function wireWin(){
 [].forEach.call(document.querySelectorAll('[data-winclear]'),function(x){
  x.onclick=function(){setWin(null,null);};});
}
/* The way out of a filter that emptied the grid, offered by emptyNote(). */
function wireEmpty(){
 var a=document.getElementById('allsev');
 if(a)a.onclick=function(){
  SEV.forEach(function(s){st.sev[s]=true;});
  chips();tRender();};
}
/* Handlers for everything viewHead() drew: the histogram columns, the filter
   pills and the detail pane's close control. */
function wireHead(){
 wireHisto();
 wireWin();
 [].forEach.call(document.querySelectorAll('#vhead [data-clear]'),function(x){
  var k=x.getAttribute('data-clear');
  x.onclick=function(){st[k]=(k==='bucket'||k==='sel')?null:'';tRender();};});
 [].forEach.call(document.querySelectorAll('#vhead [data-tech]'),function(x){
  x.onclick=function(){st.tech=x.getAttribute('data-tech');setView('findings');};});
}
/* A findings row opens itself in the detail pane; every other grid is read in
   place, so a click there would only take the row out from under you.

   This is its own function because tRefresh() replaces the whole tbody - on
   every keystroke in the row filter, every column filter and every sort - and
   the handlers go with the elements they were attached to. Wiring the rows
   only in tWire() left every grid dead the moment it was filtered: the rows
   redrew, the click did nothing, and the evidence pane kept showing whatever
   was open before. Anything that rebuilds the body must call this after. */
function wireRows(){
 if(isView(TB[st.table])!=='findings')return;
 [].forEach.call(document.querySelectorAll('tbody tr'),function(tr){
  tr.onclick=function(){
   st.sel=TLAST[+tr.getAttribute('data-r')];
   var vh=document.getElementById('vhead');
   if(vh){vh.innerHTML=viewHead();wireHead();}
   [].forEach.call(document.querySelectorAll('tbody tr.sel'),function(o){
    o.classList.remove('sel');});
   tr.classList.add('sel');};});
}
function tWire(){
 wireHead();
 wireRows();
 [].forEach.call(document.querySelectorAll('#hdr th'),function(th){
  th.onclick=function(){var i=+th.getAttribute('data-i');
   if(sortCol===i){sortAsc=!sortAsc;}else{sortCol=i;sortAsc=true;}
   /* repaint the sort arrows in place rather than re-rendering the head,
      which would take the filter inputs and their values with it */
   [].forEach.call(document.querySelectorAll('#hdr th'),function(o){
    var j=+o.getAttribute('data-i');
    o.querySelector('.lbl').textContent=TB[st.table].columns[j]+
     (sortCol===j?(sortAsc?' \\u25b2':' \\u25bc'):'');});
   tRefresh();};});
 [].forEach.call(document.querySelectorAll('tr.f input'),function(inp){
  var i=+inp.getAttribute('data-i');
  inp.oninput=function(){colFilters[i]=inp.value;tRefresh();};
  /* the input lives inside a th whose click handler sorts - without this,
     clicking into a filter box would reorder the table under the cursor */
  inp.onclick=function(e){e.stopPropagation();};});
 var q=el('q');
 if(q)q.oninput=function(){st.tq=q.value;tRefresh();};
 var clr=document.getElementById('clr');
 if(clr){clr.onclick=function(){
  colFilters=[];st.tq='';var qq=el('q');if(qq)qq.value='';
  [].forEach.call(document.querySelectorAll('tr.f input'),function(i){i.value='';});
  tRefresh();};}
 /* glue the filter row to the bottom of the label row, measured rather than
    assumed - the label height moves with the font and the zoom level */
 var hdr=document.getElementById('hdr'),frow=document.getElementById('frow');
 if(hdr&&frow){
  var top=hdr.getBoundingClientRect().height;
  [].forEach.call(frow.querySelectorAll('th'),function(th){th.style.top=top+'px';});}
}

start();
"""


def _triage_payload(tri, opts):
    """The collection header the console shows beside its charts.

    Everything else it needs - the findings, the timeline, the offensive-tool
    hits - is read out of the FINDINGS, TIMELINE and HACKTOOL_* tables, which
    the builder produces for the CSV and JSON exports anyway. Embedding a second copy for
    the page to read would double the largest part of the file and give the
    two copies a way to disagree with each other.
    """
    return {"meta": [[k, str(v)] for k, v in tri.meta.items() if v]}
