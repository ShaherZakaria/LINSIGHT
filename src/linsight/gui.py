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
/* Two themes, one set of names. Every colour in this page is a token, so a
   theme is a block that redefines the tokens rather than a second stylesheet
   to keep in step with the first. The examiner's choice is remembered because
   a console that reverts to dark on every reload is one they stop switching. */
html[data-theme="light"]{--bg:#f6f8fa;--panel:#ffffff;--panel2:#eef1f5;
--line:#d3dae2;--fg:#1c2330;--dim:#5b6775;--accent:#0969da;--gold:#9a6700;
--edge:#5b6775;--edgehot:#0969da;
--CRITICAL:#cf222e;--HIGH:#bc4c00;--MEDIUM:#9a6700;--LOW:#0a7c8c;--INFO:#5b6775;
--key:#cf222e;--interesting:#9a6700;--suspect:#bc4c00;--benign:#1a7f37;--sunk:#f6f8fa;--selbg:#ddeaff;--onbg:#ddeaff;--zebra:#f2f5f8;--hover:#e7edf4;--shadow:rgba(31,45,61,.16)}
.themebtn{border:1px solid var(--line);background:var(--panel2);color:var(--fg);
border-radius:4px;padding:2px 9px;cursor:pointer;font-size:12px}
:root{--bg:#0f1419;--panel:#161b22;--panel2:#1c2330;--line:#2b3440;--fg:#d7dee7;
--dim:#8b98a8;--accent:#58a6ff;--gold:#f5d067;
--CRITICAL:#ff5f56;--HIGH:#ff9f43;--MEDIUM:#ffd93d;--LOW:#5ad1e6;--INFO:#8b98a8;--key:#ff5f56;--interesting:#f5d067;--suspect:#ff9f43;--benign:#3fb950;--edge:#7f90a6;--edgehot:#8fc7ff;--sunk:#0d1117;--selbg:#233043;--onbg:#10243d;--zebra:#12171e;--hover:#1a212b;--shadow:rgba(0,0,0,.45)}
/* A marked row is coloured along its leading edge rather than washed
   through: the severity colours already carry meaning in these grids,
   and tinting the whole row would put the examiner's opinion and the
   tool's finding in the same visual channel. */
tr.mk{box-shadow:inset 3px 0 0 0 var(--mkc)}
tr.mk td:first-child{background:color-mix(in srgb,var(--mkc) 12%,transparent)}
tr.mk-key{--mkc:var(--key)}tr.mk-interesting{--mkc:var(--interesting)}
tr.mk-suspect{--mkc:var(--suspect)}tr.mk-benign{--mkc:var(--benign);opacity:.55}
.ntc{width:62px;text-align:center;cursor:pointer;user-select:none}
.ntc .g{opacity:.16;font-size:12px}.ntc:hover .g{opacity:.8}
.ntc .hasnote{color:var(--accent);font-size:12px}
tr.mk .mkc .g{opacity:1;color:var(--mkc)}
/* the note editor, opened in place under its row */
tr.noterow td{background:var(--panel2);padding:8px 10px}
tr.noterow textarea{width:100%;min-height:52px;background:var(--panel);
border:1px solid var(--line);color:var(--fg);border-radius:4px;
padding:6px 8px;font:12px/1.4 inherit}
.noterow .hint{color:var(--dim);font-size:11px;margin-top:4px}
tr.pivot,tbody.pivot tr[data-r]{cursor:pointer}
tr.pivot:hover>td,tbody.pivot tr[data-r]:hover>td{background:var(--panel2)}
/* Under the row it belongs to, and outside the table's layout. Reading a
   match means reading it where it sits, so the panel is anchored to the row
   that was clicked - but it is positioned rather than inserted, so the grid
   never reflows around it. Inserted as a row, a real click cost 283ms of
   layout in a grid of a thousand; positioned, the same click costs half a
   millisecond and the table is not touched at all. */
#pvpane{position:absolute;z-index:6;
background:var(--panel2);border:1px solid var(--accent);border-radius:5px;
box-shadow:0 8px 22px rgba(0,0,0,.34);
padding:9px 12px;max-height:46vh;overflow:auto;display:none}
#pvpane.on{display:block}
#pvpane .x{float:right;cursor:pointer;color:var(--dim);font-size:15px;
line-height:1;padding:0 3px}
#pvpane .x:hover{color:var(--fg)}
.pvbody{overflow:auto}
#askq{width:100%;min-height:60px;background:var(--panel);color:var(--fg);
border:1px solid var(--line);border-radius:5px;padding:8px 10px;
font:13px/1.5 inherit;resize:vertical}
.askrow{display:flex;gap:8px;align-items:center;margin:9px 0;flex-wrap:wrap}
.askans{background:var(--panel2);border:1px solid var(--line);border-radius:5px;
padding:11px 13px;margin-top:11px;white-space:pre-wrap;line-height:1.55}
.askstep{font-size:11.5px;color:var(--dim);padding:2px 0;
border-left:2px solid var(--line);padding-left:9px;margin:3px 0}
.askstep b{color:var(--accent);font-weight:600}
.asksql{color:var(--fg);white-space:pre-wrap;word-break:break-word}
.skills{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0 4px}
.skill{background:var(--panel);border:1px solid var(--line);border-radius:5px;
padding:5px 9px;font-size:12px;color:var(--fg);cursor:pointer;text-align:left}
.skill:hover{border-color:var(--accent);color:var(--accent)}
.skill.thin{opacity:.55}
.skill b{font-weight:600}
.skill i{font-style:normal;color:var(--dim);font-size:11px}
.askbad{background:rgba(255,95,86,.10);border:1px solid #ff5f56;
border-radius:5px;padding:9px 12px;margin-top:11px;font-size:12.5px;
line-height:1.5;color:var(--fg)}
.askbad b{color:#ff5f56}
.askturn{border-left:2px solid var(--line);padding-left:11px;margin:14px 0}
.askq{color:var(--dim);font-size:12px;margin-bottom:6px}
.askq b{color:var(--fg);font-weight:600}
.evkv{width:100%;border-collapse:collapse;font-size:11.5px}
.evkv th{text-align:left;color:var(--dim);font-weight:normal;width:132px;
padding:1px 10px 1px 0;white-space:nowrap;vertical-align:top}
.evkv td{padding:1px 0;color:var(--fg);vertical-align:top;
word-break:break-all;white-space:pre-wrap;overflow-wrap:anywhere}
.evsrc{color:var(--accent);font-size:11px;margin:2px 0 4px}
.evgo{margin-top:9px;display:flex;gap:7px;align-items:center;flex-wrap:wrap}
.mkc{width:104px;text-align:center;cursor:pointer;user-select:none}
.mkc .g{opacity:.18;font-size:13px}tr.mk .mkc .g{opacity:1;color:var(--mkc)}
.mkc:hover .g{opacity:.75}
.mkbar{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin:8px 0}
.mkbtn{border:1px solid var(--line);background:var(--panel2);color:var(--fg);
border-radius:4px;padding:3px 9px;cursor:pointer;font-size:12px}
.mkbtn.on{border-color:var(--mkc,var(--accent));color:var(--mkc,var(--accent))}
.lbl-chip{background:var(--panel2);border:1px solid var(--line);border-radius:10px;
padding:1px 8px;font-size:11px;color:var(--dim);margin-right:4px;cursor:pointer}
.lbl-chip.on{color:var(--accent);border-color:var(--accent)}
.score{display:inline-block;min-width:34px;text-align:right;font-variant-numeric:tabular-nums}
.sbar{display:inline-block;height:7px;border-radius:3px;background:var(--accent);
vertical-align:middle;margin-left:6px}
.gt{width:100%;overflow-x:auto;background:var(--panel);border:1px solid var(--line);
border-radius:6px;padding:10px}
.gt svg{display:block}
.gt .lane{fill:var(--dim);font-size:10px}
.gt rect.ev{cursor:pointer}
.casebar{display:flex;gap:8px;align-items:center;margin:0 0 10px}
.casebar input{background:var(--panel2);border:1px solid var(--line);color:var(--fg);
border-radius:4px;padding:4px 8px}
.mkcard{background:var(--panel);border:1px solid var(--line);border-radius:6px;
padding:10px 12px;margin:0 0 12px}
.mkcard.mk{box-shadow:inset 4px 0 0 0 var(--mkc)}
.mkhead{display:flex;gap:8px;align-items:center;margin-bottom:8px}
.mkstate{font-weight:600;color:var(--mkc,var(--fg))}
.grow{flex:1}
#hdr th.mkc,#hdr th.ntc{cursor:default;color:var(--dim)}
table.rkv{width:100%;border-collapse:collapse;margin:4px 0 8px}
table.rkv th{text-align:left;color:var(--dim);font-weight:500;width:150px;
vertical-align:top;padding:2px 8px 2px 0;white-space:nowrap;font-size:12px}
table.rkv td{padding:2px 0;vertical-align:top;word-break:break-word;
font-family:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace;font-size:12px}
.lbl-in{background:var(--panel2);border:1px solid var(--line);color:var(--fg);
border-radius:4px;padding:3px 8px;font-size:12px;min-width:240px}
.mkmeta{margin:6px 0;color:var(--dim);font-size:12px}
/* the panel grid: compact cards that answer one question each */
.panels{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));
gap:12px;margin:10px 0}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:6px;
padding:10px 12px;min-height:90px}
.panel h4{margin:0 0 8px;font-size:12px;color:var(--dim);font-weight:600;
text-transform:uppercase;letter-spacing:.04em}
.panel .big{font-size:26px;font-weight:600;line-height:1.1}
.panel .sub{color:var(--dim);font-size:12px;margin-top:2px}
.panel ol{margin:0;padding-left:18px;font-size:12px}
.panel li{margin:2px 0;word-break:break-all}
.panel .rowline{display:flex;justify-content:space-between;gap:8px;
font-size:12px;padding:2px 0;border-bottom:1px solid var(--line)}
.panel .rowline:last-child{border-bottom:0}
.panel .v{color:var(--dim);font-variant-numeric:tabular-nums;white-space:nowrap}
.pbar{height:6px;border-radius:3px;background:var(--line);overflow:hidden;margin-top:6px}
.pbar i{display:block;height:100%;background:var(--accent)}
.note-in{width:100%;background:var(--panel2);border:1px solid var(--line);
color:var(--fg);border-radius:4px;padding:6px 8px;font:12px/1.4 inherit}
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
/* The collection picker, for an export merged from several images. Beside
   the window and the chips because it is the same kind of control: one choice
   that narrows every grid at once, rather than a per-table box. */
.hf{display:flex;align-items:center;gap:5px;flex:0 0 auto}
.hf .lb{color:var(--dim);font-size:10px;letter-spacing:.6px;text-transform:uppercase}
.hf select{background:var(--panel2);color:var(--fg);border:1px solid var(--line);
border-radius:4px;padding:2px 6px;font:11px/1.6 inherit;outline:none;max-width:190px}
.hf select:focus{border-color:var(--accent)}
.hf select.on{border-color:var(--gold);color:var(--gold)}
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
box-shadow:0 10px 30px var(--shadow)}
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
main{flex:1;overflow:auto;padding:16px 18px;min-width:0;position:relative}
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
.heat .c{height:15px;border-radius:2px;background:var(--hover)}
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
.tbl tbody tr.sel td{background:var(--selbg);box-shadow:inset 3px 0 0 var(--gold)}
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
.badge{background:var(--sunk);border:1px solid var(--line);border-radius:11px;padding:2px 9px;
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
.tbl th{background:var(--panel2);position:sticky;top:0;z-index:4;cursor:pointer;user-select:none;
white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tbl th:hover{color:var(--accent)}
/* the per-column filter row sits directly under the labels; its offset is set
   from the measured label height in wire(), because the two rows have to stay
   glued together when the body scrolls under them */
.tbl tr.f th{background:var(--panel);padding:3px 4px;cursor:auto;z-index:3}
.tbl tr.f th:hover{color:inherit}
.tbl tr.f input{width:100%;background:var(--sunk);border:1px solid var(--line);color:var(--fg);
border-radius:3px;padding:2px 5px;font:11px/1.5 inherit}
.tbl tr.f input:focus{outline:none;border-color:var(--accent)}
.tbl tr.f input.on{border-color:var(--accent);background:var(--onbg);color:var(--fg)}
button.clr{background:var(--sunk);border:1px solid var(--line);color:var(--dim);
border-radius:11px;padding:2px 9px;font-size:11px;cursor:pointer}
button.clr:hover{color:var(--accent);border-color:var(--accent)}
.tbl tbody tr:nth-child(even){background:var(--zebra)}
.tbl tbody tr:hover{background:var(--hover)}
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
  if(!t||t.rows!==undefined)return;
  if(!PACK[n]&&!D.served)return;
  if(want.indexOf(n)<0)want.push(n);});
 if(!want.length)return Promise.resolve();
 /* Served, the rows live in the database rather than in this page. Asked for
    when a table is opened and not before, which is what lets the served
    console start in a moment instead of carrying the whole export. */
 if(D.served){
  return Promise.all(want.map(function(n){
   if(!PENDING[n]){
    PENDING[n]=fetch('/api/rows?table='+encodeURIComponent(n))
     .then(function(r){return r.json();})
     .then(function(j){
      TB[n].rows=(j&&j.rows)||[];
      if(j&&j.columns&&j.columns.length)TB[n].columns=j.columns;
     },function(err){
      TB[n].rows=[];TB[n].decode_error=String(err&&err.message||err);});}
   return PENDING[n];}));
 }
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
/* The cross-host tables, strongest claim first. A shared indicator or a shared
   key says these collections are one incident; a shared technique says they
   were worked the same way, which is weaker and much more often innocent. */
var CROSS=['CROSS_SESSIONS','CROSS_PATHS','CROSS_COMMANDS','CROSS_TRANSFERS',
           'CROSS_IOCS','CROSS_WEB_CLIENTS','CROSS_WEB_REQUESTS','CROSS_HASHES',
           'CROSS_KEYS','CROSS_PRIVILEGE','CROSS_ACCOUNTS','CROSS_PERSISTENCE',
           'CROSS_FINDINGS','CROSS_TECHNIQUES','HOSTS'];
function crossTables(){
 return CROSS.filter(function(n){return TB[n]&&TB[n].row_count;});
}
function haveCross(){return crossTables().length>0;}
var st={view:null,sev:{},cat:'',tech:'',sel:null,table:null,tq:'',gq:'',host:'',
        t0:null,t1:null};   /* t0/t1: the time window, epoch seconds, inclusive */
SEV.forEach(function(s){st.sev[s]=true;});
var VIEWS=[['overview','Overview'],['findings','Findings'],['attack','ATT&CK'],
           ['timeline','Timeline'],['correlation','Correlation'],
           ['graph','Graph'],['entities','Relationships'],['context','Context'],
           ['panels','Panels'],
           ['iocs','IOC score'],
           ['marked','Case'],['search','Search all'],['ask','Ask']];


/* ------------------------------------------------------------------ marks
   An investigation is the findings plus what the examiner decided about
   them, and until now the second half had nowhere to live. A mark is a
   state, any number of labels and a note, attached to one row of one table.

   The row is identified by its content, not its position: a re-run that
   reorders a table keeps its marks, and a row whose values changed loses
   them - which is correct both ways round, because the mark belongs to the
   evidence rather than to the offset it sat at.

   Served by --serve, marks go to the case file over the API and survive the
   browser. Opened as a file, they go to localStorage and survive a reload.
   The same page does both so that neither mode is a different product. */
var MK_GLYPH={key:'<span class="g">\u2605</span>',interesting:'<span class="g">\u25c6</span>',suspect:'<span class="g">\u25b2</span>',benign:'<span class="g">\u2713</span>'};
var MK_STATES=[['key','Key evidence'],['interesting','Interesting'],
               ['suspect','Suspicious'],['benign','Reviewed - benign']];
var marks={}, caseInfo={}, served=false;

function h32(str){                       /* FNV-1a, enough to name a row */
 var h=0x811c9dc5;
 for(var i=0;i<str.length;i++){h^=str.charCodeAt(i);h=(h*0x01000193)>>>0;}
 return h.toString(16);
}
function mkKey(tname,row){
 var parts=[];
 for(var i=0;i<row.length;i++){var v=row[i];parts.push(v==null?'':String(v));}
 return tname+'|'+h32(parts.join(String.fromCharCode(1)));
}
function mkGet(tname,row){return marks[mkKey(tname,row)]||null;}
/* What a mark carries with it.
   A mark that stored only "FINDINGS, row 41" is worth nothing the moment the
   table is rebuilt, and worth little even now - the examiner reading the case
   back wants the evidence, not a reference to it. So the whole row travels
   into the case: its columns, its values and the clock it was placed on.
   Long values are capped rather than dropped, because a case file that grew
   to the size of the export would stop being something you can hand over. */
var MK_CELL_CAP=4000;
function rowRef(t,row,when){
 var cols=[],vals=[];
 for(var i=0;i<t.columns.length;i++){
  var v=row[i];if(v===undefined||v===null||v==='')continue;
  v=String(v);
  cols.push(t.columns[i]);
  vals.push(v.length>MK_CELL_CAP?v.slice(0,MK_CELL_CAP)+'\u2026':v);}
 return {table:t.name,columns:cols,row:vals,when:when||'',
         what:vals.slice(0,3).join(' ')};
}
function mkClass(m){return m&&m.state?' mk mk-'+m.state:'';}

function mkSave(key,entry,where){
 if(entry&&!entry.state&&!(entry.note||'')&&!(entry.labels||[]).length)entry=null;
 /* The row travels with the mark in memory, not only in the request.
    Sending 'where' to the server while storing an entry without it meant the
    case file was right and the page was wrong: the Case view read
    marks[k].where, found nothing, and showed a mark with a note and no
    evidence until the console was reloaded. */
 if(entry)entry.where=where||entry.where||null;
 if(entry)marks[key]=entry; else delete marks[key];
 if(served){
  try{
   fetch('/api/mark',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({key:key,state:entry?entry.state:'',
     note:entry?entry.note:'',labels:entry?entry.labels:[],where:where||null})});
  }catch(e){}
 }else{
  try{localStorage.setItem(mkStoreKey(),JSON.stringify(marks));}catch(e){}
 }
}
function mkStoreKey(){
 var m=(D.meta||[]),host='';
 for(var i=0;i<m.length;i++)if(m[i][0]==='Hostname')host=m[i][1];
 return 'linsight.case.'+h32(host+'|'+(D.version||''));
}
function mkLoad(cb){
 served=!!D.served;
 if(served){
  fetch('/api/case').then(function(r){return r.json();}).then(function(j){
   marks=(j&&j.marks)||{};caseInfo=(j&&j.case)||{};cb&&cb();
  }).catch(function(){served=false;mkLoadLocal();cb&&cb();});
 }else{mkLoadLocal();cb&&cb();}
}
function mkLoadLocal(){
 try{marks=JSON.parse(localStorage.getItem(mkStoreKey())||'{}')||{};}catch(e){marks={};}
}
function mkCycle(tname,row,where){       /* click a row's marker to advance it */
 var key=mkKey(tname,row),cur=marks[key],at=-1;
 for(var i=0;i<MK_STATES.length;i++)if(cur&&cur.state===MK_STATES[i][0])at=i;
 var next=at+1>=MK_STATES.length?null:MK_STATES[at+1][0];
 var entry=next?{state:next,note:cur?cur.note||'':'',labels:cur?cur.labels||[]:[]}:null;
 mkSave(key,entry,where);
 return entry;
}
function mkAllLabels(){
 var seen={},out=[];
 for(var k in marks){(marks[k].labels||[]).forEach(function(l){
  if(!seen[l]){seen[l]=1;out.push(l);}});}
 return out.sort();
}

/* --------------------------------------------------------------- scoring
   Which indicators deserve the next hour. Frequency alone ranks the noisiest
   string on the host - a distribution path mentioned in every log - so it is
   only one term of four, and the analyst's own marks outweigh all of them.

   Deliberately transparent rather than clever: every component is printed
   beside the score, because a ranking an examiner cannot audit is a ranking
   they are right to ignore. */
function iocScores(){
 var t=T('IOCS'),rows=t?t.rows:[],out=[];
 if(!t)return out;
 var ci_=function(n){return t.columns.indexOf(n);};
 var iInd=ci_('indicator'),iType=ci_('type'),iCount=ci_('count'),
     iWhy=ci_('why'),iFirst=ci_('first_utc'),iSrc=ci_('source');
 var fin=T('FINDINGS'),fsev=fin?fin.columns.indexOf('severity'):-1,
     fev=fin?fin.columns.indexOf('evidence'):-1,
     fti=fin?fin.columns.indexOf('title'):-1;
 var sevW={CRITICAL:40,HIGH:25,MEDIUM:12,LOW:5,INFO:1};
 /* one pass over the findings, not one per indicator */
 var hay=[];
 if(fin)fin.rows.forEach(function(r){
  hay.push([String(r[fev]||'')+' '+String(r[fti]||''),sevW[r[fsev]]||0]);});
 rows.forEach(function(r){
  var ind=String(r[iInd]==null?'':r[iInd]);
  if(!ind||ind.length<4)return;
  var n=parseInt(r[iCount],10)||0;
  var freq=n>0?Math.min(20,Math.round(Math.log(1+n)*5)):0;
  var sev=0,hits=0;
  for(var i=0;i<hay.length;i++){
   if(hay[i][0].indexOf(ind)>=0){sev=Math.max(sev,hay[i][1]);hits++;}}
  var type=String(r[iType]||'');
  var kind=/ip|domain|url|hash/i.test(type)?12:/path|file/i.test(type)?6:3;
  var m=marks['IOC|'+h32(ind)];
  var mk=m?(m.state==='key'?60:m.state==='interesting'?30:
            m.state==='suspect'?40:m.state==='benign'?-100:0):0;
  var score=freq+sev+kind+mk+Math.min(12,hits*2);
  out.push({ind:ind,type:type,count:n,score:score,freq:freq,sev:sev,
            kind:kind,mk:mk,hits:hits,why:String(r[iWhy]||''),
            first:String(r[iFirst]||''),src:String(r[iSrc]||''),state:m?m.state:''});
 });
 out.sort(function(a,b){return b.score-a.score;});
 return out;
}
function T(name){
 /* Rows arrive gzipped and are unpacked per table on first use. A view that
    needs one it has not seen asks for it, returns nothing this paint, and is
    redrawn when the rows land - which is why every caller handles null. */
 var t=TB[name];
 if(!t)return null;
 if(t.rows!==undefined)return t;
 T._p=T._p||{};
 if(!T._p[name]){T._p[name]=1;
  ensure([name]).then(function(){T._p[name]=0;draw();});}
 return null;
}

/* --------------------------------------------------- the graph timeline
   The table timeline answers "what happened at 03:14". This answers "what
   does the whole intrusion look like", which is the question you ask before
   you know which minute matters.

   One lane per category, one rect per event, severity as colour and the
   examiner's marks drawn on top - so an afternoon of marking becomes a shape
   rather than a list. Drawn as SVG by hand: a charting library would be a
   network fetch, and this page has to open on a machine that has none. */
function viewGraph(){
 var src=T('TIMELINE')||T('FINDINGS');
 if(!src)return '<div class="pad">Loading the timeline…</div>';
 var ci_=function(n){return src.columns.indexOf(n);};
 var iT=ci_('timestamp_utc'),iC=ci_('category'),iS=ci_('severity'),
     iW=ci_('what')>=0?ci_('what'):ci_('detail');
 if(iT<0)return '<div class="pad">The timeline has no timestamp column.</div>';
 var ev=[],lo=null,hi=null;
 src.rows.forEach(function(r){
  var e=ts(r[iT]);if(e===null)return;
  if(lo===null||e<lo)lo=e; if(hi===null||e>hi)hi=e;
  ev.push({t:e,c:String(r[iC]||'other'),s:String(r[iS]||'INFO'),
           w:String(r[iW]||''),row:r});});
 if(!ev.length)return '<div class="pad">No dated events.</div>';
 if(hi===lo)hi=lo+60;
 var lanes=[],seen={};
 ev.forEach(function(e){if(!seen[e.c]){seen[e.c]=1;lanes.push(e.c);}});
 lanes.sort();
 var W=Math.max(900,lanes.length?1100:900),LH=26,PAD=140,H=lanes.length*LH+42;
 var x=function(tt){return PAD+(W-PAD-20)*(tt-lo)/(hi-lo);};
 var h='<div class="pad"><h3>Intrusion shape</h3>'+
   '<div class="dim" style="margin-bottom:8px">'+ev.length.toLocaleString()+
   ' dated event(s), '+lanes.length+' categor'+(lanes.length===1?'y':'ies')+
   ', '+fmtT(lo)+' to '+fmtT(hi)+
   ' &mdash; click any event to mark it</div><div class="gt"><svg width="'+W+
   '" height="'+H+'" viewBox="0 0 '+W+' '+H+'">';
 /* hour/day gridlines, whichever the span justifies */
 var span=hi-lo,step=span>86400*8?86400*Math.ceil(span/86400/10):
                     span>3600*8?3600*Math.ceil(span/3600/10):600;
 for(var g=Math.ceil(lo/step)*step;g<hi;g+=step){
  h+='<line x1="'+x(g).toFixed(1)+'" y1="16" x2="'+x(g).toFixed(1)+'" y2="'+
     (H-14)+'" stroke="var(--line)" stroke-width="1"/>';
  h+='<text x="'+(x(g)+3).toFixed(1)+'" y="12" class="lane">'+
     esc(fmtT(g).slice(5,16))+'</text>';}
 lanes.forEach(function(c,i){
  var y=24+i*LH;
  h+='<text x="6" y="'+(y+13)+'" class="lane">'+esc(c.slice(0,20))+'</text>';
  h+='<line x1="'+PAD+'" y1="'+(y+LH-1)+'" x2="'+(W-20)+'" y2="'+(y+LH-1)+
     '" stroke="var(--line)" stroke-width="1" opacity=".4"/>';});
 ev.forEach(function(e,i){
  var li=lanes.indexOf(e.c),y=24+li*LH+4,m=mkGet(src.name,e.row);
  var col=m&&m.state?'var(--'+m.state+')':'var(--'+e.s+')';
  var w=m&&m.state?5:3;
  h+='<rect class="ev" data-i="'+i+'" x="'+(x(e.t)-w/2).toFixed(1)+'" y="'+y+
     '" width="'+w+'" height="'+(LH-9)+'" rx="1.5" fill="'+col+
     '" opacity="'+(m&&m.state==='benign'?.3:m&&m.state?1:.72)+'"><title>'+
     esc(fmtT(e.t)+'  ['+e.s+'] '+e.c+' | '+e.w.slice(0,160))+'</title></rect>';});
 h+='</svg></div>';
 h+='<div class="mkbar" style="margin-top:10px">';
 MK_STATES.forEach(function(st_){
  h+='<span class="lbl-chip" style="border-color:var(--'+st_[0]+
     ');color:var(--'+st_[0]+')">'+esc(st_[1])+'</span>';});
 h+='<span class="dim">severity colours where unmarked</span></div></div>';
 GEV=ev;GSRC=src;
 return h;
}
var GEV=[],GSRC=null;

/* ------------------------------------------------------------ IOC score */
function viewIocs(){
 if(!T('IOCS'))return '<div class="pad">Loading indicators…</div>';
 var sc=iocScores();
 if(!sc.length)return '<div class="pad">No indicators were extracted. '+
   'Run with --count-iocs to count every one across the collection.</div>';
 var top=sc.slice(0,300),max=top[0].score||1;
 var h='<div class="pad"><h3>Indicators by score</h3>'+
  '<div class="dim" style="margin-bottom:10px">'+sc.length.toLocaleString()+
  ' indicator(s) ranked by how much they look like the thing worth chasing: '+
  'how often they appear, the worst severity of a finding that names them, '+
  'what kind of indicator they are, and how you have marked them. '+
  'Every term is shown - a ranking you cannot audit is one you should '+
  'ignore. Click a row to mark it.</div>';
 h+='<table class="grid"><thead><tr><th>score</th><th>indicator</th>'+
    '<th>type</th><th>seen</th><th>why</th><th>first</th></tr></thead><tbody>';
 top.forEach(function(r,i){
  var m=marks['IOC|'+h32(r.ind)];
  h+='<tr class="ioc'+mkClass(m)+'" data-ioc="'+esc(r.ind)+'">'+
   '<td class="num"><span class="score">'+r.score+'</span>'+
   '<span class="sbar" style="width:'+Math.max(2,Math.round(46*r.score/max))+
   'px"></span></td>'+
   '<td><code>'+esc(r.ind.slice(0,90))+'</code></td>'+
   '<td>'+esc(r.type)+'</td>'+
   '<td class="num" title="frequency '+r.freq+' + severity '+r.sev+
   ' + kind '+r.kind+' + marks '+r.mk+' + findings '+r.hits+'">'+
   (r.count||'')+'</td>'+
   '<td>'+esc(r.why.slice(0,80))+'</td><td class="nw">'+esc(r.first)+'</td></tr>';});
 h+='</tbody></table></div>';
 return h;
}

/* ------------------------------------------------- the relationship graph
   The time ribbon answers "when". This answers "who touched what", which is
   the question that turns a list of events into an intrusion you can follow:
   an address reaches an account, that account escalates to another, and
   something owned by one of them is sitting in a temp directory.

   Edges are only drawn where an artifact actually recorded the relation -
   nothing here is inferred - and every node carries the count of rows that
   put it there, so a thick edge is evidence and not a guess.

   The layout is a small force simulation run to a fixed iteration count
   rather than animated: it has to settle the same way twice so that a
   screenshot in a report matches what the examiner saw. */
var NODE_KIND={ip:'#58a6ff',user:'#f5d067',file:'#ff9f43',rule:'#ff5f56',cmd:'#a371f7',url:'#3fb950',tool:'#ff7b72',host:'#79c0ff',collection:'#79c0ff'};
var EGN=44;        /* how many circles to draw - the examiner's choice */
var EGISO=null;    /* the node the picture is narrowed to, by key */
/* Which kinds of thing are drawn. All of them to start, because the first
   question is "what is here"; the second is always "show me fewer", and
   before this the only answer was the circle count - which drops the
   *smallest* nodes rather than the kind you did not want. Twelve command
   nodes crowding out two addresses is the common case, and no number of
   circles fixes it. */
var EGKIND={ip:1,user:1,file:1,cmd:1,url:1,tool:1,rule:1,collection:1};
/* The rows behind the last picture, so the caption can say what it was drawn
   from. A filter that changes little still has to look applied. */
var EGSRC={rows:0,tables:0};
/* Whether to draw a circle per collection. On by default in a merged export,
   because that is the picture worth opening one for - but a switch, because
   a hub joined to twenty entities is a hub, and on a busy host it is the
   thing standing between the reader and everything else. */
var EGHUBS=true;
/* Whether to write what each line means along it. On below a threshold and
   off above it, because "ip -> account" with no verb on it is a picture of
   connections rather than of activity - and a hundred labels at once is a
   picture of nothing. */
var EGLBL=null;        /* null = decide from the edge count */
function egLabels(){
 return EGLBL===null?(EG&&EG.edges.length<=34):EGLBL;
}
function egHubs(){
 return !!(EGHUBS&&HOSTS.length>1&&HOSTCOL&&!hostOn()&&EGKIND.collection);
}
/* Rows the graph is allowed to draw from. The collection picker reaches here
   like it reaches every grid - a picture still drawn over three hosts while
   the rest of the console shows one would be answering a question nobody
   asked. */
function egRows(t){
 if(!t)return [];
 var rows=hostFilter(t.rows,t);
 EGSRC.rows+=rows.length;
 if(rows.length)EGSRC.tables++;
 return rows;
}
/* Which activity wins when one pair of entities did several things. Success
   outranks failure because it is the answer to a different question - not
   "was this address trying" but "did it get in". */
function _egRank(why){
 var w=String(why||'').toLowerCase();
 if(w.indexOf('accepted')>=0||w.indexOf('success')>=0)return 4;
 if(w.indexOf('privilege')>=0||w.indexOf('sudo')>=0)return 3;
 if(w.indexOf('failed')>=0)return 1;
 return w?2:0;
}
/* An activity that succeeded is drawn differently from one that did not.
   Colour rather than a footnote, because on a busy picture the question is
   always which of these lines mattered. */
function egEdgeColour(e){
 if(e.kind==='move')return 'var(--gold)';
 if(e.kind==='in')return NODE_KIND.collection;
 var w=String(e.why||'').toLowerCase();
 if(w.indexOf('accepted')>=0||w.indexOf('success')>=0)return 'var(--HIGH)';
 if(w.indexOf('privilege')>=0||w.indexOf('sudo')>=0)return 'var(--MEDIUM)';
 return 'var(--edge)';
}
function egBuild(){
 var nodes={},edges={},order=[];
 EGSRC={rows:0,tables:0};
 /* Six rows kept per node and per edge, so hovering can show the evidence
    rather than a count of it. Six because that is what fits in the panel -
    the full set is one click away in the table it names. */
 var KEEP=6;
 function node(kind,id,extra){
  if(!EGKIND[kind])return null;
  var k=kind+':'+id;
  if(!nodes[k]){nodes[k]={k:k,kind:kind,id:id,n:0,extra:extra||'',ev:[]};
   order.push(nodes[k]);}
  nodes[k].n++;return nodes[k];}
 function evid(o,ctx){
  if(ctx&&o.ev.length<KEEP)o.ev.push(ctx);}
 /* `why` is the activity, and it is now the edge's own property rather than
    a string hidden in a tooltip: it is drawn on the line, it colours the
    line, and it is what the legend of relations counts. `kind` separates the
    three sorts of line the picture holds - an observed activity, an entity
    being present in a collection, and one collection reached after another,
    which are three different claims and were all one grey line. */
 function edge(a,b,why,ctx,kind){
  if(!a||!b||a===b)return null;
  var k=a.k+'>'+b.k;
  if(!edges[k])edges[k]={a:a,b:b,n:0,why:why||'',ev:[],
                         kind:kind||'act',whys:{}};
  var e=edges[k];
  e.n++;
  if(why)e.whys[why]=(e.whys[why]||0)+1;
  /* A pair seen doing several things keeps the most telling one: a source
     that failed forty times and succeeded once is a source that got in, and
     an edge labelled 'failed password' would say the opposite. */
  if(_egRank(why)>_egRank(e.why))e.why=why;
  evid(e,ctx);evid(a,ctx);evid(b,ctx);
  seen(a,ctx);seen(b,ctx);
  return e;}
 /* Which collections a node was observed in. Read off the row rather than
    tracked per source, because one node is reached from several tables and
    the answer has to be the union of all of them. */
 function seen(o,ctx){
  if(!HOSTCOL||!ctx||!ctx.c)return;
  var i=ctx.c.indexOf(HOSTCOL);
  if(i<0)return;
  var v=ctx.r[i];
  if(v){if(!o.hosts)o.hosts={};o.hosts[v]=1;}}

 /* an address that authenticated, and the account it reached */
 var au=T('AUTH_LOG');
 if(au){
  var ei=au.columns.indexOf('event'),ui=au.columns.indexOf('user'),
      si=au.columns.indexOf('source_ip');
  egRows(au).forEach(function(r){
   var ev=String(r[ei]||'');
   if(ev.indexOf('accepted')<0&&ev.indexOf('failed')<0)return;
   var ip=String(r[si]||''),us=String(r[ui]||'');
   if(!ip||!us)return;
   edge(node('ip',ip),node('user',us),ev,{t:'AUTH_LOG',c:au.columns,r:r});});}

 /* an account that became another account */
 var pa=T('PRIVILEGE_ACTIVITY');
 if(pa){
  var ai=pa.columns.indexOf('actor'),ti=pa.columns.indexOf('target_user');
  egRows(pa).forEach(function(r){
   var a=String(r[ai]||''),b=String(r[ti]||'');
   if(!a||!b)return;
   edge(node('user',a),node('user',b),'privilege',
        {t:'PRIVILEGE_ACTIVITY',c:pa.columns,r:r});});}

 /* something an account owns, sitting where payloads are dropped */
 var bf=T('BODYFILE');
 if(bf){
  var pi=bf.columns.indexOf('path'),oi=bf.columns.indexOf('owner'),
      mi=bf.columns.indexOf('mode');
  egRows(bf).forEach(function(r){
   var p=String(r[pi]||'');
   if(p.indexOf('/tmp/')<0&&p.indexOf('/var/tmp/')<0&&p.indexOf('/dev/shm/')<0)return;
   if(String(r[mi]||'').indexOf('x')<0)return;
   if(String(r[mi]||'').charAt(0)==='d')return;
   var o=String(r[oi]||'');if(!o)return;
   edge(node('user',o),node('file',p),'owns an executable in tmp',
        {t:'BODYFILE',c:bf.columns,r:r});});}

 /* a rule that fired, tied to the table it fired on */
 var sm=T('SIGMA_MATCHES');
 if(sm){
  var ri=sm.columns.indexOf('rule'),mr=sm.columns.indexOf('matched_row');
  egRows(sm).forEach(function(r){
   var rule=String(r[ri]||''),row=String(r[mr]||'');
   if(!rule)return;
   var m=row.match(/(?:user|actor|owner)=([A-Za-z0-9_.-]+)/);
   if(m)edge(node('rule',rule.slice(0,44)),node('user',m[1]),'rule',
            {t:'SIGMA_MATCHES',c:sm.columns,r:r});
   var ipm=row.match(/([0-9]{1,3}(?:[.][0-9]{1,3}){3})/);
   if(ipm)edge(node('rule',rule.slice(0,44)),node('ip',ipm[1]),'rule',
              {t:'SIGMA_MATCHES',c:sm.columns,r:r});});}

 /* what a scheduled job runs, and as whom */
 var cr=T('CRON');
 if(cr){
  var ri2=cr.columns.indexOf('run_as'),ci2=cr.columns.indexOf('command');
  egRows(cr).forEach(function(r){
   var who=String(r[ri2]||''),cmd=String(r[ci2]||'');
   if(!who||!cmd)return;
   edge(node('user',who),node('cmd',cmd.slice(0,46)),'scheduled job',
        {t:'CRON',c:cr.columns,r:r});});}

 /* what somebody typed, and as whom */
 var sh=T('SHELL_HISTORY');
 if(sh){
  var ui2=sh.columns.indexOf('user'),cc=sh.columns.indexOf('command');
  egRows(sh).forEach(function(r){
   var who=String(r[ui2]||''),cmd=String(r[cc]||'');
   if(!who||!cmd||cmd.length<4)return;
   edge(node('user',who),node('cmd',cmd.slice(0,46)),'shell history',
        {t:'SHELL_HISTORY',c:sh.columns,r:r});});}

 /* what the web server actually answered, and to whom */
 var wl=T('WEB_LOG');
 if(wl){
  var wi=wl.columns.indexOf('client_ip'),rs=wl.columns.indexOf('resource'),
      sti=wl.columns.indexOf('status');
  egRows(wl).forEach(function(r){
   if(String(r[sti]||'').charAt(0)!=='2')return;      /* answered, not probed */
   var ip=String(r[wi]||''),res=String(r[rs]||'');
   if(!ip||!res)return;
   edge(node('ip',ip),node('url',res.slice(0,46)),'answered 2xx',
        {t:'WEB_LOG',c:wl.columns,r:r});});}

 /* offensive tooling, tied to the table that named it */
 var hk=T('HACKTOOL_HITS');
 if(hk){
  var hti=hk.columns.indexOf('tool'),hwi=hk.columns.indexOf('table');
  egRows(hk).forEach(function(r){
   var tool=String(r[hti]||''),where=String(r[hwi]||'');
   if(!tool||!where)return;
   edge(node('tool',tool),node('file',where),'named in',
        {t:'HACKTOOL_HITS',c:hk.columns,r:r});});}

 /* ---- the correlation, drawn ----
    An entity observed in more than one collection gets an edge to each of
    them. Only those: linking every node to its collection would double the
    picture and say nothing, since most nodes belong to exactly one. What is
    left is the shape an examiner opens three disks to see - the collection
    hubs with the addresses, accounts and files that bridge them strung
    between, and everything private to one host hanging off its own side.
    Skipped when a single collection is picked: there is then nothing to
    bridge, and the rows have already been filtered to it. */
 if(egHubs()){
  order.slice().forEach(function(nd){
   if(nd.kind==='collection'||!nd.hosts)return;
   var hs=[],hh;
   for(hh in nd.hosts)hs.push(hh);
   if(hs.length<2)return;
   hs.forEach(function(hn){
    edge(node('collection',hn),nd,'seen in this collection',null,'in');});});

  /* ---- lateral movement ----
     The one relation in this picture that is about time rather than about
     structure: an indicator observed on one collection before another, drawn
     from the correlation's own CROSS_IOCS - first_host to last_host, with an
     arrow, because "web01 and db02 share an address" and "it reached db02
     forty minutes after web01" are different sentences and only the second
     one says which way the intrusion travelled.

     Read from the table rather than recomputed here: the correlation already
     did this arithmetic against each run's resolved UTC offset, and a second
     implementation of it would be a second chance to get it wrong. */
  var xi=T('CROSS_IOCS');
  if(xi){
   var ai=xi.columns.indexOf('first_host'),bi=xi.columns.indexOf('last_host'),
       ii=xi.columns.indexOf('indicator'),gi=xi.columns.indexOf('spread');
   if(ai>=0&&bi>=0)xi.rows.forEach(function(r){
    var a=String(r[ai]||''),b=String(r[bi]||''),gap=String(r[gi]||'');
    if(!a||!b||a===b)return;
    var e=edge(node('collection',a),node('collection',b),
               String(r[ii]||'')+(gap?' after '+gap:''),
               {t:'CROSS_IOCS',c:xi.columns,r:r},'move');
    if(e&&gap&&!e.gap)e.gap=gap;});}}

 /* Narrowed to one thing and what it touches. Done here rather than by
    dimming the rest, because dimming leaves every unrelated circle taking up
    its space and the layout unchanged - and the question "what does this file
    touch" is answered by a picture of that and nothing else. The neighbours'
    edges to each other are kept: they are part of the neighbourhood, and
    dropping them would draw a star where the artifacts recorded a mesh. */
 if(EGISO&&nodes[EGISO]){
  var hub=nodes[EGISO],near={};
  near[hub.k]=1;
  for(var ik in edges){
   var ie=edges[ik];
   if(ie.a===hub)near[ie.b.k]=1;
   if(ie.b===hub)near[ie.a.k]=1;}
  order=order.filter(function(nd){return near[nd.k];});}

 /* keep it readable: the busiest nodes and any edge between two survivors */
 order.sort(function(a,b){return b.n-a.n;});
 var keep={},top=order.slice(0,EGN);
 top.forEach(function(nd){keep[nd.k]=1;});
 var es=[];
 for(var k in edges){
  var e=edges[k];
  if(keep[e.a.k]&&keep[e.b.k])es.push(e);}
 return {nodes:top,edges:es};
}
/* Which declared arrowhead goes with which stroke colour. */
var EGMK={'var(--edge)':0,'var(--HIGH)':1,'var(--MEDIUM)':2,
          'var(--gold)':3,'var(--edgehot)':4};
/* A line from the edge of one circle to the edge of the next, leaving room
   for the arrowhead. Centre-to-centre buries the head under the target. */
function egSeg(e){
 var dx=e.b.x-e.a.x,dy=e.b.y-e.a.y,d=Math.sqrt(dx*dx+dy*dy)||1;
 var ux=dx/d,uy=dy/d,ar=(e.a.r||8)+2,br=(e.b.r||8)+7;
 if(ar+br>d-4){ar=Math.max(0,(d-4)/2);br=ar;}
 return {x1:e.a.x+ux*ar,y1:e.a.y+uy*ar,
         x2:e.b.x-ux*br,y2:e.b.y-uy*br};
}
function egLayout(g,W,H){
 var i,j,n=g.nodes.length;
 if(!n)return;
 g.nodes.forEach(function(nd,ix){          /* deterministic ring start */
  var a=2*Math.PI*ix/n;
  nd.x=W/2+Math.cos(a)*Math.min(W,H)*0.34;
  nd.y=H/2+Math.sin(a)*Math.min(W,H)*0.34;});
 for(var step=0;step<220;step++){
  for(i=0;i<n;i++){
   var A=g.nodes[i],fx=0,fy=0;
   for(j=0;j<n;j++){                       /* repulsion */
    if(i===j)continue;
    var B=g.nodes[j],dx=A.x-B.x,dy=A.y-B.y,d2=dx*dx+dy*dy||1;
    var f=2400/d2;fx+=dx*f;fy+=dy*f;}
   fx+=(W/2-A.x)*0.012;fy+=(H/2-A.y)*0.012;   /* gravity */
   A.vx=fx;A.vy=fy;}
  g.edges.forEach(function(e){              /* springs */
   var dx=e.b.x-e.a.x,dy=e.b.y-e.a.y,d=Math.sqrt(dx*dx+dy*dy)||1;
   var f=(d-110)*0.02;
   e.a.vx+=dx/d*f;e.a.vy+=dy/d*f;
   e.b.vx-=dx/d*f;e.b.vy-=dy/d*f;});
  for(i=0;i<n;i++){
   var N=g.nodes[i];
   N.x=Math.max(60,Math.min(W-60,N.x+Math.max(-9,Math.min(9,N.vx))));
   N.y=Math.max(26,Math.min(H-26,N.y+Math.max(-9,Math.min(9,N.vy))));}}
}
var EG=null;          /* the laid-out graph, kept so handlers can move it */
var EGHUB=null;       /* the narrowed-to node, once it has been found */
function viewEntities(){
 if(!panelsReady())return '<div class="pad"><h3>Relationships</h3>'+
   '<div class="dim">Unpacking the artifact tables\u2026</div></div>';
 EG=egBuild();
 EGHUB=null;
 EG.nodes.forEach(function(nd){if(nd.k===EGISO)EGHUB=nd;});
 /* Narrowed to something this data no longer holds - the circle count moved
    it out, or a table was unpacked since. Rather than an empty canvas, widen
    back out and say nothing is narrowed. */
 if(EGISO&&!EGHUB){EGISO=null;EG=egBuild();}
 if(!EG.nodes.length)return '<div class="pad"><h3>Relationships</h3>'+
   '<div class="dim">Nothing in this collection records a relation between '+
   'an address, an account and a file.</div></div>';
 var W=1180,H=620;
 egLayout(EG,W,H);
 EG.W=W;EG.H=H;EG.view=[0,0,W,H];EG.focus=null;
 var maxn=EG.edges.reduce(function(m,e){return Math.max(m,e.n);},1);
 /* Sized before the edges are drawn, not with them: a line has to stop short
    of the circle it points at or the arrowhead lands underneath it. */
 EG.nodes.forEach(function(nd){
  nd.r=7+Math.min(12,Math.log(1+nd.n)*2.6);});
 var kinds=[['ip','address'],['user','account'],['file','file'],
            ['cmd','command'],['url','answered URL'],['tool','tool'],
            ['rule','rule']];
 if(egHubs())kinds.push(['collection','collection']);
 var h='<div class="pad"><h3>Relationships</h3>'+
  '<div class="mkbar">';
 /* The legend is the filter. It was a colour key and nothing else, which
    meant the only way to get a readable picture out of a busy host was to
    turn the circle count down and lose the small nodes - including the two
    addresses the whole question was about. Clicking a kind now drops it. */
 kinds.forEach(function(k){
  var on=!!EGKIND[k[0]];
  h+='<span class="lbl-chip'+(on?'':' off')+'" data-egk="'+k[0]+
     '" style="cursor:pointer;border-color:'+NODE_KIND[k[0]]+';color:'+
     (on?NODE_KIND[k[0]]:'var(--dim)')+(on?'':';opacity:.45')+
     '" title="show or hide '+esc(k[1])+' circles">'+esc(k[1])+'</span>';});
 h+='<span class="grow"></span>';
 if(HOSTS.length>1&&HOSTCOL&&!hostOn())
  h+='<button class="mkbtn'+(EGHUBS?' on':'')+'" id="eg_hubs" '+
     'title="draw a circle per collection, joined to whatever was seen in '+
     'more than one of them">collections</button>';
 h+='<button class="mkbtn'+(egLabels()?' on':'')+'" id="eg_lbls" '+
    'title="write what each line means along it">labels</button>';
 [25,50,100,200].forEach(function(n){
  h+='<button class="mkbtn'+(EGN===n?' on':'')+'" data-egn="'+n+'">'+n+
     '</button>';});
 h+='<span class="dim">circles</span>'+
   '<button class="mkbtn" id="eg_reset">reset</button>'+
   (EGISO&&EGHUB
    ?'<button class="mkbtn on" id="eg_all">show everything</button>'+
     '<span class="dim">showing <b>'+esc(EGHUB.id)+'</b> and what it touches'+
     '</span>'
    :'')+
   '<span class="dim">drag a node \u00b7 hover to isolate \u00b7 click one to see only it '+
   '\u00b7 wheel to zoom</span></div>';
 h+='<div class="dim" style="margin-bottom:6px">'+EG.nodes.length+
   ' entities, '+EG.edges.length+' observed relation(s), drawn from '+
   EGSRC.rows.toLocaleString()+' row(s) in '+EGSRC.tables+' table(s)'+
   (hostOn()?' of collection <b>'+esc(st.host)+'</b>'
    :HOSTS.length>1?' across all '+HOSTS.length+' collections':'')+
   '. Arrows point the way the activity went - an address to the account it '+
   'reached, an account to the one it became, a collection to the one an '+
   'indicator reached after it. Thickness is how many rows recorded the '+
   'relation; <b style="color:var(--HIGH)">orange</b> is an authentication '+
   'that succeeded and <b style="color:var(--MEDIUM)">yellow</b> a privilege '+
   'change. Nothing here is inferred.'+
   (egHubs()
    ?' The pale-blue circles are the collections themselves: a dashed line '+
     'means the thing was observed in that collection, and a '+
     '<b style="color:var(--gold)">gold arrow between two of them</b> is '+
     'lateral movement - an indicator that reached the second one after the '+
     'first, labelled with how long it took.'
    :'')+
   (kinds.some(function(k){return !EGKIND[k[0]];})
    ?' <b>'+kinds.filter(function(k){return !EGKIND[k[0]];})
      .map(function(k){return esc(k[1]);}).join(', ')+
     '</b> hidden \u2014 click the labels to bring them back.'
    :'')+'</div>';
 h+='<div class="gt" id="eg_wrap"><svg id="eg" width="100%" height="'+H+
    '" viewBox="0 0 '+W+' '+H+'">';
 /* One arrowhead per colour the edges use. SVG markers cannot inherit the
    line's stroke in every browser this has to open in, so they are declared
    rather than derived. */
 h+='<defs>';
 ['var(--edge)','var(--HIGH)','var(--MEDIUM)','var(--gold)','var(--edgehot)']
  .forEach(function(c,ci){
  h+='<marker id="egar'+ci+'" viewBox="0 0 10 10" refX="9" refY="5" '+
     'markerWidth="5" markerHeight="5" orient="auto-start-reverse">'+
     '<path d="M0,0 L10,5 L0,10 z" fill="'+c+'"/></marker>';});
 h+='</defs>';
 h+='<g id="eg_edges">';
 EG.edges.forEach(function(e,i){
  var p=egSeg(e),c=egEdgeColour(e),move=(e.kind==='move');
  h+='<line data-e="'+i+'" x1="'+p.x1.toFixed(1)+'" y1="'+p.y1.toFixed(1)+
     '" x2="'+p.x2.toFixed(1)+'" y2="'+p.y2.toFixed(1)+
     '" stroke="'+c+'" stroke-width="'+
     (e.kind==='in'?1:move?2.6:(1.4+3*e.n/maxn)).toFixed(2)+
     (e.kind==='in'?'" stroke-dasharray="4 4':'')+
     '" marker-end="url(#egar'+EGMK[c]+')"'+
     ' opacity="'+(e.kind==='in'?'.35':'.9')+'"><title>'+
     esc(e.a.id+' \u2192 '+e.b.id+'  ('+e.n+' row(s), '+
         (e.kind==='move'?'reached after ':'')+e.why+')')+
     '</title></line>';});
 h+='</g><g id="eg_lbl">';
 if(egLabels())EG.edges.forEach(function(e,i){
  if(e.kind==='in')return;                 /* 'seen in' on every line is noise */
  var p=egSeg(e);
  h+='<text data-l="'+i+'" x="'+((p.x1+p.x2)/2).toFixed(1)+'" y="'+
     (((p.y1+p.y2)/2)-3).toFixed(1)+'" text-anchor="middle" '+
     'style="font-size:9.5px;fill:'+egEdgeColour(e)+
     ';paint-order:stroke;stroke:var(--bg);stroke-width:3px;pointer-events:none"'+
     '>'+esc(String(e.why||'').slice(0,34))+'</text>';});
 h+='</g><g id="eg_nodes">';
 EG.nodes.forEach(function(nd,i){
  h+='<g class="egn" data-n="'+i+'" style="cursor:grab">';
  h+='<circle cx="'+nd.x.toFixed(1)+'" cy="'+nd.y.toFixed(1)+'" r="'+
     nd.r.toFixed(1)+'" fill="'+NODE_KIND[nd.kind]+'" stroke="var(--bg)" '+
     'stroke-width="2"><title>'+esc(nd.kind+' '+nd.id+' \u2014 '+nd.n+
     ' row(s)')+'</title></circle>';
  h+='<text x="'+(nd.x+nd.r+4).toFixed(1)+'" y="'+(nd.y+4).toFixed(1)+
     '" class="lane" style="font-size:11px;paint-order:stroke;stroke:var(--bg);'+
     'stroke-width:3px">'+esc(String(nd.id).slice(0,30))+'</text>';
  h+='</g>';});
 h+='</g></svg></div>';
 h+=egPanels(EG);
 h+='<div id="eg_det" class="mkcard" style="margin-top:10px">'+
   '<div class="dim">Hover a node or a line to see the rows that put it there.</div></div>';
 h+='</div>';
 return h;
}
/* Three questions the picture alone does not answer: what kinds of thing are
   in it, which of them sit at the centre, and what the lines actually mean.
   Computed from the graph that was just laid out, so they can never disagree
   with what is on screen. */
function egPanels(g){
 var byKind={},deg={},byWhy={};
 g.nodes.forEach(function(n){byKind[n.kind]=(byKind[n.kind]||0)+1;deg[n.k]=0;});
 g.edges.forEach(function(e){
  deg[e.a.k]=(deg[e.a.k]||0)+e.n;deg[e.b.k]=(deg[e.b.k]||0)+e.n;
  byWhy[e.why||'relation']=(byWhy[e.why||'relation']||0)+e.n;});
 var top=g.nodes.slice().sort(function(a,b){
  return (deg[b.k]||0)-(deg[a.k]||0);}).slice(0,7);
 var h='<div class="panels" style="margin-top:12px">';
 h+='<div class="panel"><h4>Entity mix</h4>';
 Object.keys(byKind).sort(function(a,b){return byKind[b]-byKind[a];})
  .forEach(function(k){
   h+='<div class="rowline"><span><span style="color:'+NODE_KIND[k]+
      '">\u25cf</span> '+esc(k)+'</span><span class="v">'+byKind[k]+
      '</span></div>';});
 h+='</div>';
 h+='<div class="panel"><h4>Most connected</h4>';
 top.forEach(function(n){
  h+='<div class="rowline"><span><span style="color:'+NODE_KIND[n.kind]+
     '">\u25cf</span> '+esc(String(n.id).slice(0,30))+'</span>'+
     '<span class="v">'+(deg[n.k]||0)+'</span></div>';});
 h+='</div>';
 h+='<div class="panel"><h4>Relations by kind</h4>';
 Object.keys(byWhy).sort(function(a,b){return byWhy[b]-byWhy[a];}).slice(0,7)
  .forEach(function(w){
   h+='<div class="rowline"><span>'+esc(w)+'</span><span class="v">'+
      byWhy[w]+'</span></div>';});
 h+='</div></div>';
 return h;
}
/* Dragging, hovering and focusing, done against the SVG that is already on
   the page rather than by re-rendering it: a graph that jumps back to its
   starting positions every time it is touched is one an examiner stops
   touching. */
function egWire(){
 var svg=document.getElementById('eg');
 if(!svg||!EG)return;
 var nodes=[].slice.call(svg.querySelectorAll('.egn'));
 var lines=[].slice.call(svg.querySelectorAll('#eg_edges line'));
 var drag=null;

 function place(i){
  var nd=EG.nodes[i],g=nodes[i];
  g.querySelector('circle').setAttribute('cx',nd.x.toFixed(1));
  g.querySelector('circle').setAttribute('cy',nd.y.toFixed(1));
  var t=g.querySelector('text');
  t.setAttribute('x',(nd.x+nd.r+4).toFixed(1));
  t.setAttribute('y',(nd.y+4).toFixed(1));
  EG.edges.forEach(function(e,ei){
   if(e.a!==nd&&e.b!==nd)return;
   var L=lines[ei],p=egSeg(e);
   L.setAttribute('x1',p.x1.toFixed(1));L.setAttribute('y1',p.y1.toFixed(1));
   L.setAttribute('x2',p.x2.toFixed(1));L.setAttribute('y2',p.y2.toFixed(1));
   var lb=svg.querySelector('#eg_lbl [data-l="'+ei+'"]');
   if(lb){lb.setAttribute('x',((p.x1+p.x2)/2).toFixed(1));
          lb.setAttribute('y',(((p.y1+p.y2)/2)-3).toFixed(1));}});
 }
 function svgPoint(ev){
  var r=svg.getBoundingClientRect(),v=EG.view;
  return {x:v[0]+(ev.clientX-r.left)/r.width*v[2],
          y:v[1]+(ev.clientY-r.top)/r.height*v[3]};
 }
 function neighbours(nd){
  var set={};set[nd.k]=1;
  EG.edges.forEach(function(e){
   if(e.a===nd)set[e.b.k]=1;
   if(e.b===nd)set[e.a.k]=1;});
  return set;
 }
 function highlight(nd){
  if(!nd){
   nodes.forEach(function(g){g.style.opacity=1;});
   lines.forEach(function(L,i){
    var e=EG.edges[i],c=egEdgeColour(e);
    L.style.opacity=(e.kind==='in')?0.35:0.9;
    L.setAttribute('stroke',c);
    L.setAttribute('marker-end','url(#egar'+EGMK[c]+')');});
   return;}
  var keep=neighbours(nd);
  EG.nodes.forEach(function(n2,i){
   nodes[i].style.opacity=keep[n2.k]?1:0.12;});
  EG.edges.forEach(function(e,i){
   var on=(e.a===nd||e.b===nd),c=on?'var(--edgehot)':egEdgeColour(e);
   lines[i].style.opacity=on?1:0.07;
   lines[i].setAttribute('stroke',c);
   lines[i].setAttribute('marker-end','url(#egar'+EGMK[c]+')');});
 }
 function evHtml(title,sub,ev){
  var h='<div class="mkhead"><span class="mkstate">'+esc(title)+
        '</span><span class="dim">'+esc(sub)+'</span></div>';
  if(!ev||!ev.length)return h+'<div class="dim">No sample rows kept.</div>';
  ev.forEach(function(x){
   h+='<div class="dim" style="margin:6px 0 2px"><span class="badge">'+
      esc(x.t)+'</span></div><table class="rkv">';
   for(var i=0;i<x.c.length;i++){
    var v=x.r[i];
    if(v===undefined||v===null||v==='')continue;
    h+='<tr><th>'+esc(x.c[i])+'</th><td>'+esc(String(v).slice(0,300))+
       '</td></tr>';}
   h+='</table>';});
  return h;
 }
 function detail(html){
  var d=document.getElementById('eg_det');
  if(d)d.innerHTML=html;
 }
 lines.forEach(function(L,i){
  L.onmouseenter=function(){
   var e=EG.edges[i];
   detail(evHtml(e.a.id+'  \u2192  '+e.b.id,
     e.n+' row(s) recorded this - '+e.why,e.ev));};});
 nodes.forEach(function(g,i){
  g.onmouseenter=function(){
   if(!drag&&!EG.focus)highlight(EG.nodes[i]);
   var nd=EG.nodes[i];
   detail(evHtml(nd.kind+'  '+nd.id,nd.n+' row(s) name it',nd.ev));};
  g.onmouseleave=function(){if(!drag&&!EG.focus)highlight(null);};
  g.onmousedown=function(ev){
   ev.preventDefault();drag={i:i,moved:false};g.style.cursor='grabbing';};
  g.onclick=function(ev){
   ev.stopPropagation();
   if(drag&&drag.moved)return;          /* a drag that happened to end here */
   var nd=EG.nodes[i];
   /* clicking the one already narrowed to widens back out; clicking any
      other narrows to it, which is what makes a run of clicks a walk */
   EGISO=(EGISO===nd.k)?null:nd.k;
   draw();};});
 svg.onmousemove=function(ev){
  if(!drag)return;
  var p=svgPoint(ev),nd=EG.nodes[drag.i];
  nd.x=p.x;nd.y=p.y;drag.moved=true;place(drag.i);};
 svg.onmouseup=function(){
  if(drag)nodes[drag.i].style.cursor='grab';
  drag=null;};
 svg.onmouseleave=function(){drag=null;};
 svg.onclick=function(){EG.focus=null;highlight(null);};
 svg.onwheel=function(ev){
  ev.preventDefault();
  var v=EG.view,f=ev.deltaY>0?1.12:0.89,p=svgPoint(ev);
  var w=Math.max(200,Math.min(EG.W*3,v[2]*f)),hh=w*EG.H/EG.W;
  EG.view=[p.x-(p.x-v[0])*(w/v[2]),p.y-(p.y-v[1])*(hh/v[3]),w,hh];
  svg.setAttribute('viewBox',EG.view.join(' '));};
 [].forEach.call(document.querySelectorAll('button[data-egn]'),function(b){
  b.onclick=function(){EGN=+b.getAttribute('data-egn');draw();};});
 [].forEach.call(document.querySelectorAll('[data-egk]'),function(b){
  b.onclick=function(ev){
   var k=b.getAttribute('data-egk');
   /* Alt-click isolates one kind, the way the severity chips do - "only the
      addresses and what they touch" is otherwise six clicks. */
   if((ev||window.event).altKey){
    for(var x in EGKIND)EGKIND[x]=(x===k)||(x==='collection'&&EGKIND.collection);
    EGKIND[k]=1;}
   else EGKIND[k]=EGKIND[k]?0:1;
   EGISO=null;draw();};});
 var hub=document.getElementById('eg_hubs');
 if(hub)hub.onclick=function(){EGHUBS=!EGHUBS;EGISO=null;draw();};
 var lbl=document.getElementById('eg_lbls');
 if(lbl)lbl.onclick=function(){EGLBL=!egLabels();draw();};
 var all=document.getElementById('eg_all');
 if(all)all.onclick=function(){EGISO=null;draw();};
 var rst=document.getElementById('eg_reset');
 if(rst)rst.onclick=function(){
  EGISO=null;EGHUBS=true;EGLBL=null;
  for(var x in EGKIND)EGKIND[x]=1;
  draw();};
}

/* ------------------------------------------------------------- panels
   One question per panel, each computed from a table that already exists.
   The overview answers "how bad and when"; these answer the questions an
   examiner asks next - who was hitting it, which account, what persists,
   what was touched in the window, and how much of it has been looked at. */
function pTop(t,col,n,pred){
 if(!t)return [];
 var i=t.columns.indexOf(col);if(i<0)return [];
 var c={},k;
 t.rows.forEach(function(r){
  if(pred&&!pred(r))return;
  var v=r[i];if(v===undefined||v===null||v==='')return;
  v=String(v);c[v]=(c[v]||0)+1;});
 var out=[];for(k in c)out.push([k,c[k]]);
 out.sort(function(a,b){return b[1]-a[1];});
 return out.slice(0,n||6);
}
function panelList(title,pairs,empty){
 var h='<div class="panel"><h4>'+esc(title)+'</h4>';
 if(!pairs.length)return h+'<div class="dim">'+esc(empty||'nothing here')+'</div></div>';
 var max=pairs[0][1]||1;
 pairs.forEach(function(p){
  h+='<div class="rowline"><span>'+esc(String(p[0]).slice(0,42))+
     '</span><span class="v">'+p[1].toLocaleString()+'</span></div>';});
 return h+'</div>';
}
function panelBig(title,value,sub,frac){
 var h='<div class="panel"><h4>'+esc(title)+'</h4><div class="big">'+
   esc(String(value))+'</div><div class="sub">'+esc(sub||'')+'</div>';
 if(frac!==undefined)h+='<div class="pbar"><i style="width:'+
   Math.round(Math.max(0,Math.min(1,frac))*100)+'%"></i></div>';
 return h+'</div>';
}
/* Every table a panel reads, requested together and waited for.

   A panel that renders before its table is unpacked prints 0, and 0 is a
   number an examiner will believe: "0 cron entries" on a host with 604 of
   them is not a slow page, it is a wrong answer. So the view asks for all of
   them at once and says it is loading until it can answer honestly - the same
   rule the rest of this tool follows about silence. */
var PANEL_TABLES=['FINDINGS','FAILED_LOGINS','AUTH_LOG','USERS','CRON',
                  'PRIVILEGE_ACTIVITY','BODYFILE',
                  'SYSTEMD_UNITS','INIT_AND_PROFILE','WEB_LOG','DELETED_FILES',
                  'HACKTOOL_HITS','SIGMA_MATCHES'];
function panelsReady(){
 var missing=[];
 PANEL_TABLES.forEach(function(n){
  var t=TB[n];
  if(t&&t.rows===undefined)missing.push(n);});
 if(!missing.length)return true;
 if(!panelsReady._p){
  panelsReady._p=1;
  ensure(missing).then(function(){panelsReady._p=0;draw();});}
 return false;
}
function viewPanels(){
 if(!panelsReady())return '<div class="pad"><h3>Panels</h3>'+
   '<div class="dim">Unpacking the artifact tables\u2026 '+
   'the panels wait rather than report a zero they cannot stand behind.</div></div>';
 var h='<div class="pad"><h3>Panels</h3><div class="dim">'+
  'Each panel is computed from an artifact table - nothing here is a second '+
  'copy of the evidence. Numbers are for the whole collection unless a time '+
  'window is set.</div><div class="panels">';

 /* how much of the case has been looked at */
 var fin=T('FINDINGS');
 var marked=Object.keys(marks).length,states={};
 for(var k in marks){var st_=marks[k].state||'?';states[st_]=(states[st_]||0)+1;}
 h+=panelBig('Triaged',marked.toLocaleString(),
   Object.keys(states).map(function(x){
     return states[x]+' '+stateLabel(x).toLowerCase();}).join(', ')||
   'nothing marked yet',
   fin?marked/Math.max(1,fin.rows.length):0);

 /* severity mix */
 if(fin){
  var si=fin.columns.indexOf('severity'),cnt={};
  fin.rows.forEach(function(r){var v=r[si];cnt[v]=(cnt[v]||0)+1;});
  var pairs=SEV.filter(function(x){return cnt[x];}).map(function(x){
    return [x,cnt[x]];});
  h+=panelList('Findings by severity',pairs,'no findings');}

 /* who was hitting it */
 var fl=T('FAILED_LOGINS');
 h+=panelList('Top sources - failed auth',pTop(fl,'source_ip',6),
   'no failed logins recorded');
 var au=T('AUTH_LOG');
 if(au){
  var ei=au.columns.indexOf('event');
  h+=panelList('Accepted logins by user',
    pTop(au,'user',6,function(r){
      return String(r[ei]||'').indexOf('accepted')>=0;}),
    'no accepted logins');}

 /* which accounts exist to be abused */
 var us=T('USERS');
 if(us){
  var pi=us.columns.indexOf('privileged_groups'),
      li=us.columns.indexOf('login_capable');
  var priv=us.rows.filter(function(r){return String(r[pi]||'').trim();}).length;
  var able=us.rows.filter(function(r){
    return String(r[li]||'').toLowerCase()==='yes';}).length;
  h+=panelBig('Accounts',us.rows.length,
    priv+' in a privileged group, '+able+' able to log in',
    priv/Math.max(1,us.rows.length));}

 /* what runs without being asked */
 var cr=T('CRON'),su=T('SYSTEMD_UNITS'),ip=T('INIT_AND_PROFILE');
 h+=panelBig('Persistence surface',
   ((cr?cr.rows.length:0)+(su?su.rows.length:0)+
    (ip?ip.rows.length:0)).toLocaleString(),
   (cr?cr.rows.length:0)+' cron, '+(su?su.rows.length:0)+' unit, '+
   (ip?ip.rows.length:0)+' init/profile line(s)');

 /* what the web was asked for */
 var wl=T('WEB_LOG');
 if(wl){
  var sti=wl.columns.indexOf('status');
  var ok=wl.rows.filter(function(r){
    return String(r[sti]||'').charAt(0)==='2';}).length;
  h+=panelBig('Web requests',wl.rows.length.toLocaleString(),
    ok.toLocaleString()+' answered 2xx',ok/Math.max(1,wl.rows.length));
  h+=panelList('Most requested',pTop(wl,'resource',6),'no requests');}

 /* what was deleted, and what is hidden */
 var df=T('DELETED_FILES');
 if(df)h+=panelBig('Deleted inodes',df.rows.length.toLocaleString(),
   'recovered from the inode tables - dated and sized, not named');
 var hk=T('HACKTOOL_HITS');
 if(hk)h+=panelList('Offensive tooling named',pTop(hk,'tool',6),'none named');

 /* the rules that fired */
 var sm=T('SIGMA_MATCHES');
 if(sm)h+=panelList('Rules fired',pTop(sm,'rule',6),'no rule matched');

 h+='</div></div>';
 return h;
}

/* ----------------------------------------------------------- the case view
   Everything marked, in time order, with its note. This is the view an
   examiner writes the report out of, so it carries the note and the label
   rather than only the colour. */
function viewMarked(){
 var keys=Object.keys(marks);
 var h='<div class="pad"><h3>Case</h3>';
 h+='<div class="casebar"><input id="cs_name" placeholder="case name" value="'+
   esc(caseInfo.name||'')+'"><input id="cs_an" placeholder="examiner" value="'+
   esc(caseInfo.examiner||'')+'"><span class="dim">'+
   (served?'saved to the case file':'saved in this browser')+'</span></div>';
 var vs=caseInfo.views||[];
 if(vs.length){
  h+='<div class="mkbar">saved views: ';
  vs.forEach(function(v){
   h+='<button class="mkbtn" data-view="'+esc(v.name)+'">'+esc(v.name)+
      '</button>';});
  h+='</div>';}
 if(!keys.length){
  h+='<p class="dim">Nothing marked yet. Click the marker in the first '+
     'column of any grid, or an event on the Graph, to cycle it through '+
     MK_STATES.map(function(x){return x[1];}).join(' &rarr; ')+'.</p></div>';
  return h;}
 var labels=mkAllLabels();
 if(labels.length){
  h+='<div class="mkbar">labels: ';
  labels.forEach(function(l){
   h+='<span class="lbl-chip'+(st.label===l?' on':'')+'" data-lbl="'+esc(l)+
      '">'+esc(l)+'</span>';});
  h+='</div>';}
 var items=keys.map(function(k){
  var m=marks[k];return {k:k,m:m,w:m.where||{}};}).filter(function(it){
  return !st.label||(it.m.labels||[]).indexOf(st.label)>=0;});
 items.sort(function(a,b){
  var A=(a.w.when||a.m.updated||''),B=(b.w.when||b.m.updated||'');
  return A<B?-1:A>B?1:0;});
 h+='<div class="dim" style="margin:6px 0">'+items.length+' marked item(s)</div>';
 items.forEach(function(it){
  var w=it.w,cols=w.columns||[],vals=w.row||[];
  h+='<div class="mkcard mk mk-'+esc(it.m.state||'interesting')+'" data-k="'+
     esc(it.k)+'">';
  h+='<div class="mkhead"><span class="mkstate">'+esc(stateLabel(it.m.state))+
     '</span><span class="badge">'+esc(w.table||it.k.split('|')[0])+'</span>'+
     (w.when?'<span class="dim nw">'+esc(w.when)+'</span>':'')+
     '<span class="grow"></span>'+
     (w.when?'<button class="mkbtn" data-ctx="'+esc(w.when)+
      '">context</button>':'')+
     '<button class="mkbtn" data-cycle="'+esc(it.k)+'">state</button>'+
     '<button class="mkbtn" data-del="'+esc(it.k)+'">remove</button></div>';
  if(cols.length){
   h+='<table class="rkv">';
   for(var i=0;i<cols.length;i++){
    h+='<tr><th>'+esc(cols[i])+'</th><td>'+esc(vals[i])+'</td></tr>';}
   h+='</table>';
  }else{h+='<div class="dim">'+esc(String(w.what||''))+'</div>';}
  h+='<div class="mkmeta">labels: <input class="lbl-in" data-lbl-for="'+
     esc(it.k)+'" value="'+esc((it.m.labels||[]).join(' '))+
     '" placeholder="space separated"></div>';
  h+='<textarea class="note-in" data-note-for="'+esc(it.k)+
     '" placeholder="why this matters, what it links to">'+
     esc(it.m.note||'')+'</textarea>';
  h+='</div>';});
 h+='<div class="mkbar" style="margin-top:12px">'+
   '<button class="mkbtn" id="cs_save">Save current view</button>'+
   '<button class="mkbtn" id="cs_rep">Write report (Markdown)</button>'+
   '<button class="mkbtn" id="cs_dl">Export case JSON</button>'+
   '<span class="dim">the marks, the labels and the notes - '+
   'for the report, or to hand to the next examiner</span></div></div>';
 return h;
}
/* ------------------------------------------------------------ the report
   What every investigation platform ends with, and the reason to mark
   anything at all: the case as a document somebody else can read.

   Markdown rather than a rendered page, because the next thing that happens
   to it is that a human edits it. Ordered by the clock, not by when the
   examiner happened to click, and each entry carries the whole row - a report
   that says "see FINDINGS row 41" is a report that cannot be checked.

   Indicators are defanged on the way out. A report is a document that gets
   mailed, and a live URL in a mailed document is a link somebody clicks. */
function defang(v){
 return String(v)
  .replace(/https?:[/][/]/gi,function(m){return m.replace('t','x').replace('t','x');})
  .replace(/([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})/g,
           '$1[.]$2[.]$3[.]$4')
  .replace(/[.](com|net|org|ru|cn|io|tech|xyz|top|info)(?![a-z])/gi,'[.]$1');
}
function caseReport(){
 var host='',src='';
 (D.meta||[]).forEach(function(m){
  if(m[0]==='Hostname')host=m[1];
  if(/collection|disk image/i.test(m[0])&&!src)src=m[1];});
 var L=[];
 L.push('# '+(caseInfo.name||'Investigation')+' \u2014 '+(host||'host'));
 L.push('');
 if(caseInfo.examiner)L.push('Examiner: '+caseInfo.examiner);
 L.push('Evidence: `'+(src||'')+'`');
 L.push('Generated by linsight '+(D.version||'')+' from '+
        Object.keys(marks).length+' marked item(s).');
 L.push('');
 L.push('Indicators below are defanged.');
 L.push('');

 var items=Object.keys(marks).map(function(k){
  return {k:k,m:marks[k],w:marks[k].where||{}};});
 items.sort(function(a,b){
  var A=a.w.when||a.m.updated||'',B=b.w.when||b.m.updated||'';
  return A<B?-1:A>B?1:0;});

 /* the summary an incident lead reads first */
 var byState={};
 items.forEach(function(it){
  var st_=it.m.state||'interesting';
  (byState[st_]=byState[st_]||[]).push(it);});
 L.push('## Summary');
 L.push('');
 MK_STATES.forEach(function(ms){
  var n=(byState[ms[0]]||[]).length;
  if(n)L.push('- **'+ms[1]+'**: '+n+' item(s)');});
 var labs=mkAllLabels();
 if(labs.length)L.push('- Labels used: '+labs.join(', '));
 L.push('');

 /* the timeline of what was marked */
 L.push('## Timeline of marked evidence');
 L.push('');
 items.forEach(function(it){
  var w=it.w;
  L.push('### '+(w.when||'(undated)')+' \u2014 '+stateLabel(it.m.state));
  L.push('');
  L.push('Source: `'+(w.table||'')+'`'+
    ((it.m.labels||[]).length?'  \u00b7 labels: '+it.m.labels.join(', '):''));
  L.push('');
  if(it.m.note){L.push('> '+it.m.note.split(String.fromCharCode(10)).join(' '));L.push('');}
  var cols=w.columns||[],vals=w.row||[];
  if(cols.length){
   L.push('| field | value |');
   L.push('|---|---|');
   for(var i=0;i<cols.length;i++){
    L.push('| '+cols[i]+' | `'+defang(vals[i]).replace(/[|]/g,'\\|').slice(0,400)+'` |');}
   L.push('');}
 });

 /* what the tool found, whether or not anybody marked it */
 var fin=T('FINDINGS');
 if(fin){
  var si=fin.columns.indexOf('severity'),ti=fin.columns.indexOf('title'),
      ci_=fin.columns.indexOf('count');
  var crit=fin.rows.filter(function(r){
   return r[si]==='CRITICAL'||r[si]==='HIGH';});
  if(crit.length){
   L.push('## Unmarked findings at HIGH or above');
   L.push('');
   L.push('Listed so the report says what was *not* triaged as well as what was.');
   L.push('');
   crit.forEach(function(r){
    if(mkGet('FINDINGS',r))return;
    L.push('- **'+r[si]+'** '+String(r[ti]).replace(/[|]/g,'')+
      (r[ci_]?' ('+r[ci_]+')':''));});
   L.push('');}}
 return L.join(String.fromCharCode(10));
}
/* ------------------------------------------------------------- context
   Timesketch calls it context search and it is the move an examiner makes
   the moment anything looks wrong: not "what does this table say" but "what
   else was this host doing at that second".

   Served, this is one query across every table that carries a clock, which
   is the thing the database is for. Without a database there is nothing to
   ask, so the button is simply not offered. */
var CTX=null,CTXQ=null;
function ctxOpen(when,mins){
 if(!when)return;
 st.ctx={when:String(when).slice(0,19),minutes:mins||15};
 CTX=null;st.view='context';draw();
}
function ctxForm(v){
 return '<div class="casebar"><input id="ctx_when" style="min-width:260px" '+
  'placeholder="YYYY-MM-DD HH:MM:SS" value="'+esc(v||'')+'">'+
  '<button class="mkbtn" id="ctx_go">show what happened around it</button>'+
  '<span class="dim">paste a timestamp from any grid</span></div>';
}
function viewContext(){
 var c=st.ctx;
 if(!c)return '<div class="pad"><h3>Context</h3>'+
  '<div class="dim" style="margin-bottom:10px">What else was this host doing '+
  'at one moment - asked of every table that carries a clock, in one query. '+
  'Type a time below, or press <b>context</b> on any item in the Case '+
  'view.</div>'+ctxForm('')+'</div>';
 if(!D.served)return '<div class="pad"><h3>Context</h3><div class="dim">'+
  'Context is a database query - run with --serve to use it.</div></div>';
 var key=c.when+'|'+c.minutes;
 if(!CTX||CTXQ!==key){
  if(CTXQ!==key){
   CTXQ=key;
   fetch('/api/context?when='+encodeURIComponent(c.when)+'&minutes='+c.minutes)
    .then(function(r){return r.json();}).then(function(j){CTX=j;draw();},
     function(){CTX={tables:[],total:0,error:1};draw();});}
  return '<div class="pad"><h3>Context</h3><div class="dim">Asking every '+
   'table what happened around '+esc(c.when)+'\u2026</div></div>';
 }
 var h='<div class="pad"><h3>Context</h3>'+ctxForm(c.when)+
  '<div class="mkbar"><span>around <b>'+esc(c.when)+'</b></span>';
 [5,15,60,240].forEach(function(m){
  h+='<button class="mkbtn'+(c.minutes===m?' on':'')+'" data-ctxm="'+m+
     '">\u00b1'+m+'m</button>';});
 h+='<span class="dim">'+CTX.total+' row(s) across '+CTX.tables.length+
    ' table(s)</span></div>';
 CTX.tables.forEach(function(t){
  h+='<div class="mkcard"><div class="mkhead"><span class="badge">'+
     esc(t.table)+'</span><span class="dim">'+t.rows.length+
     ' row(s) by '+esc(t.time_column)+'</span></div>';
  h+='<table class="grid"><thead><tr>';
  t.columns.forEach(function(c2){h+='<th>'+esc(c2)+'</th>';});
  h+='</tr></thead><tbody>';
  t.rows.forEach(function(r){
   h+='<tr>';
   for(var i=0;i<t.columns.length;i++){
    h+='<td><div class="c">'+esc(r[i]==null?'':r[i])+'</div></td>';}
   h+='</tr>';});
  h+='</tbody></table></div>';});
 return h+'</div>';
}

/* --------------------------------------------------------- saved views
   The other half of what makes Timesketch a workspace: a filter you reached
   once and can return to, by name, and that somebody else can open. Saved
   into the case rather than the browser, so it travels with the marks. */
function viewState(){
 return {view:st.view,table:st.table,tq:st.tq||'',cat:st.cat||'',
         tech:st.tech||'',sev:JSON.parse(JSON.stringify(st.sev||{})),
         t0:(el('t0')||{}).value||'',t1:(el('t1')||{}).value||'',
         cols:(typeof colFilters!=='undefined')?colFilters.slice():[]};
}
function saveView(name){
 if(!name)return;
 caseInfo.views=caseInfo.views||[];
 caseInfo.views=caseInfo.views.filter(function(v){return v.name!==name;});
 caseInfo.views.push({name:name,at:new Date().toISOString().slice(0,19)
   .replace('T',' '),state:viewState()});
 pushCase();draw();
}
function loadView(name){
 var v=(caseInfo.views||[]).filter(function(x){return x.name===name;})[0];
 if(!v)return;
 var q=v.state||{};
 st.view=q.view||'overview';st.table=q.table||st.table;
 st.tq=q.tq||'';st.cat=q.cat||'';st.tech=q.tech||'';
 if(q.sev)st.sev=q.sev;
 if(typeof colFilters!=='undefined')colFilters=(q.cols||[]).slice();
 if(el('t0'))el('t0').value=q.t0||'';
 if(el('t1'))el('t1').value=q.t1||'';
 if(typeof readWin==='function')readWin();
 draw();
}
function pushCase(){
 if(!D.served){try{localStorage.setItem(mkStoreKey()+'.case',
   JSON.stringify(caseInfo));}catch(e){}return;}
 try{fetch('/api/case',{method:'POST',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify(caseInfo)});}catch(e){}
}
function stateLabel(k){
 for(var i=0;i<MK_STATES.length;i++)if(MK_STATES[i][0]===k)return MK_STATES[i][1];
 return k||'';
}

function themeInit(){
 var v='dark';
 try{v=localStorage.getItem('linsight.theme')||'dark';}catch(e){}
 themeSet(v);
 var b=document.getElementById('theme');
 if(b)b.onclick=function(){
  themeSet(document.documentElement.getAttribute('data-theme')==='light'
   ?'dark':'light');};
}
function themeSet(v){
 document.documentElement.setAttribute('data-theme',v);
 try{localStorage.setItem('linsight.theme',v);}catch(e){}
 var b=document.getElementById('theme');
 if(b)b.innerHTML=(v==='light')?'&#9681;':'&#9680;';
 if(st&&st.view==='entities')draw();     /* the graph paints its own colours */
}
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
 /* Every clock in these tables is already UTC, so a bare stamp gets its Z.
    A stamp that already carries an offset keeps it - appending Z to
    '...11:04:14+00:00' produced an unparseable string and, before the
    database was taught to use the shared formatter, silently emptied the
    graph of all 2,411 of its events. */
 var v=String(s||'').trim();
 if(!v)return null;
 var iso=v.replace(' ','T');
 var d=Date.parse(/[Zz]$|[+-][0-9][0-9]:?[0-9][0-9]$/.test(iso)?iso:iso+'Z');
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

/* ---------- the collection filter ----------
   An export merged from several images carries every host's rows in one set
   of tables, each row naming the collection it came from. No selection means
   all of them, which is the useful default: the question an examiner opens
   three disks with is "what happened", not "what happened on disk 2". Picking
   one narrows every grid, both charts, the severity counts and the ATT&CK
   matrix at once - the same reach the time window has, and for the same
   reason. A table with no such column is left alone rather than emptied:
   CROSS_IOCS is about several collections by construction and filtering it to
   one would be filtering out the answer. */
var HOSTS=D.hosts||[],HOSTCOL=D.hostcol||'';
function hostOn(){return !!(st.host&&HOSTCOL);}
function hostCol(t){
 if(t._hc===undefined)t._hc=HOSTCOL?ci(t,HOSTCOL):-1;
 return t._hc;
}
function inHost(t,r){
 var i=hostCol(t);
 return i<0||r[i]===st.host;
}
function hostFilter(rows,t){
 if(!hostOn())return rows;
 var i=hostCol(t);
 if(i<0)return rows;
 return rows.filter(function(r){return r[i]===st.host;});
}
/* Rows this collection contributed to a table, for the badge that says so. */
function hostSkipped(t){
 if(!hostOn())return 0;
 var i=hostCol(t);
 if(i<0)return 0;
 var n=0;
 t.rows.forEach(function(r){if(r[i]!==st.host)n++;});
 return n;
}
function hostRender(){
 var box=el('hf');
 if(!box)return;
 if(HOSTS.length<2||!HOSTCOL){box.innerHTML='';return;}
 var h='<span class="lb">collection</span><select id="hostsel" title="'+
   'narrow every table to one of the collections in this export">'+
   '<option value="">all '+HOSTS.length+'</option>';
 HOSTS.forEach(function(x){
  h+='<option value="'+esc(x)+'"'+(st.host===x?' selected':'')+'>'+esc(x)+'</option>';});
 box.innerHTML=h+'</select>';
 var sel=el('hostsel');
 sel.className=hostOn()?'on':'';
 sel.onchange=function(){setHost(sel.value);};
}
function setHost(v){
 if(st.host===v)return;
 st.host=v;
 /* the calendar shading and the '-24h' anchor are both read off the timeline,
    so a narrower set of rows is a different calendar and a different anchor */
 DAYN=null;DMAX=null;
 hostRender();chips();render();
}
/* The latest moment anything in the collection carries, so '-24h' has an end
   to count back from. The capture is the natural anchor, not the reader's
   clock: a collection taken last year is still read as its own last day. */
var DMAX=null;
function dataMax(){
 if(DMAX!==null)return DMAX;
 DMAX=0;
 var t=vt('timeline')||vt('findings');
 if(t){
  var tc=tcols(t),hi=hostOn()?hostCol(t):-1;
  t.rows.forEach(function(r){
   if(hi>=0&&r[hi]!==st.host)return;
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
function hostBadge(t){
 if(!hostOn())return '';
 if(hostCol(t)<0)return '<span class="badge">collection filter not applied '+
   '\u2014 '+esc(t.name)+' has no per-collection rows</span>';
 var n=hostSkipped(t);
 return '<span class="badge warn">collection '+esc(st.host)+
   (n?' \u2014 '+n.toLocaleString()+' row(s) from the others hidden':'')+
   ' <span class="pill" data-hostclear="1">clear &times;</span></span>';
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
 var hi=hostOn()?hostCol(f.t):-1;
 return f.t.rows.filter(function(r){
  if(hi>=0&&r[hi]!==st.host)return false;
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
 var hi=hostOn()?hostCol(f.t):-1;
 (f.t.rows||[]).forEach(function(r){
  if(hi>=0&&r[hi]!==st.host)return;
  n[r[f.severity]]=(n[r[f.severity]]||0)+1;});
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
 var tc=tcols(t),hi=hostOn()?hostCol(t):-1;
 t.rows.forEach(function(r){
  if(hi>=0&&r[hi]!==st.host)return;
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
  /* The finding's own row opens underneath it with the artifact rows it
     came from, which is the same information this panel carried and more of
     it - two previews of one row is one too many. */
  h+='</div>';
 }else if(st.view==='timeline'){
  var t=TB[st.table];
  /* Drawn from what the chips, the row filter and the column filters left,
     but never from the window: picking a spike must not hide the shape the
     spike sits in. */
  h+=histo(tMatching(t,true),ci(t,'timestamp_utc'),ci(t,'severity'),80,132,true).html;
 }
 if(hostOn())h+='<div class="pills"><span class="pill" data-hostclear="1">'+
   'collection: '+esc(st.host)+' &times;</span></div>';
 if(winOn())h+='<div class="pills"><span class="pill" data-winclear="1">'+
   'time window: '+esc(fmtWin())+' &times;</span></div>';
 return h;
}


/* ---------- the correlation ----------
   Its own tab rather than eight grids scattered through the nav, because it
   answers one question - what do these collections have in common - and the
   answer is only worth anything read together. Each panel is the top of one
   cross-host table with a way into the full grid: the point here is to see
   that a key is shared and an address arrived in a direction, not to page
   through four hundred rows.

   Deliberately not filtered by the collection picker. Every row in here is a
   statement about several collections at once, so narrowing to one would be
   filtering out the answer - and the tab says so rather than silently
   showing less. */
function crossPanel(name,cols,fmt){
 var t=TB[name];
 if(!t||!t.row_count)return '';
 var rows=t.rows||[];
 var at={};t.columns.forEach(function(c,i){at[c]=i;});
 var h='<div class="mkcard"><div class="mkhead"><b>'+esc(t.title)+'</b>'+
   '<span class="grow"></span><span class="dim">'+
   t.row_count.toLocaleString()+' row(s)</span>'+
   '<button class="mkbtn" data-open="'+esc(name)+'">open '+esc(name)+
   '</button></div>';
 if(!rows.length)return h+'<div class="dim pad">'+
   (t.rows===undefined
    ?'decoding '+t.row_count.toLocaleString()+' row(s)\u2026'
    :'no rows')+'</div></div>';
 h+='<table class="tbl"><thead><tr>';
 cols.forEach(function(c){h+='<th>'+esc(c)+'</th>';});
 h+='</tr></thead><tbody>';
 rows.slice(0,8).forEach(function(r){
  h+='<tr>';
  cols.forEach(function(c){
   var v=at[c]===undefined?'':r[at[c]];
   h+='<td>'+(fmt?fmt(c,v,r,at):esc(String(v==null?'':v)))+'</td>';});
  h+='</tr>';});
 h+='</tbody></table>';
 if(t.row_count>8)h+='<div class="dim pad">'+(t.row_count-8).toLocaleString()+
   ' more in the full table</div>';
 return h+'</div>';
}
/* The cross-host tables are not in the set the console decodes on open, and
   they are not waited for as a set either.

   Waiting was the first cut and it was wrong. CROSS_HASHES on a real estate
   is every file three hosts have in common - tens of thousands of rows - and
   blocking eight panels on the slowest of them meant staring at "unpacking"
   while the one table nobody came for decoded. Each panel shows eight rows;
   there is no reason for the eight rows of CROSS_IOCS to wait on any of it.
   So they are decoded one at a time, in the order the tab lists them, and the
   page is redrawn as each lands. A panel that has no rows yet draws its
   heading and its count - which come from the index and need no decode at
   all - so the tab is complete from the first paint and only fills in. */
function crossWarm(){
 if(crossWarm._busy)return;
 var next=crossTables().filter(function(n){return TB[n].rows===undefined;})[0];
 if(!next)return;
 crossWarm._busy=1;
 ensure([next]).then(function(){
  crossWarm._busy=0;
  if(st.view==='correlation')draw();
  crossWarm();});
}
function viewCorrelation(){
 if(!haveCross())return '<div class="pad"><h3>Correlation</h3>'+
  '<div class="dim">This export holds one collection. Pass several - '+
  '<code>linsight.py uac1.tar disk2.dd disk3.E01 --export ./case '+
  '--correlate</code> - and this tab fills with what is true of more than '+
  'one of them.</div></div>';
 var have=crossTables();
 crossWarm();
 var hosts=TB['HOSTS'],hrows=(hosts&&hosts.rows)||[];
 var h='<div class="pad"><h3>Correlation</h3>';
 h+='<div class="dim" style="margin-bottom:8px">What is true of more than '+
   'one of these collections, and of none of them on its own. The collection '+
   'picker does not apply here: every row is a statement about several at '+
   'once.</div>';
 if(hrows.length){
  var ha={};hosts.columns.forEach(function(c,i){ha[c]=i;});
  h+='<div class="cards">';
  hrows.forEach(function(r){
   h+='<div class="card" data-hostpick="'+esc(r[ha['collection']])+'">'+
      '<b>'+esc(r[ha['collection']])+'</b><span>'+
      esc(r[ha['hostname']]||'hostname not recorded')+'</span>'+
      '<span class="dim">'+esc(r[ha['critical']]||'0')+' critical \u00b7 '+
      esc(r[ha['high']]||'0')+' high \u00b7 '+
      esc(r[ha['indicators']]||'0')+' indicators</span></div>';});
  h+='</div>';
 }
 h+=crossPanel('CROSS_SESSIONS',
   ['timestamp_utc','from_collection','to_collection','user','result','service']);
 h+=crossPanel('CROSS_PATHS',
   ['path','first_utc','last_utc','elapsed','users','result']);
 h+=crossPanel('CROSS_COMMANDS',
   ['timestamp_utc','from_collection','to_collection','user','matched','command']);
 h+=crossPanel('CROSS_TRANSFERS',
   ['from_collection','to_collection','gap','basis','to_path','first_utc']);
 h+=crossPanel('CROSS_IOCS',
   ['indicator','type','host_count','hosts','first_host','first_utc','spread']);
 h+=crossPanel('CROSS_WEB_CLIENTS',
   ['client','host_count','hosts','requests','answered','first_utc','spread']);
 h+=crossPanel('CROSS_WEB_REQUESTS',
   ['method','resource','host_count','hosts','requests','answered','status_codes']);
 h+=crossPanel('CROSS_KEYS',
   ['key_type','fingerprint_head','host_count','hosts']);
 h+=crossPanel('CROSS_HASHES',
   ['digest','host_count','hosts','notable','same_path','paths']);
 h+=crossPanel('CROSS_PRIVILEGE',
   ['kind','grant','host_count','hosts','notable','nopasswd']);
 h+=crossPanel('CROSS_ACCOUNTS',
   ['username','uid','host_count','hosts','consistent','shells']);
 h+=crossPanel('CROSS_PERSISTENCE',['kind','value','host_count','hosts']);
 h+=crossPanel('CROSS_FINDINGS',
   ['severity','category','finding','host_count','hosts'],
   function(c,v){
    if(c==='severity')return '<b style="color:var(--'+esc(v)+')">'+esc(v)+'</b>';
    return esc(String(v==null?'':v));});
 h+=crossPanel('CROSS_TECHNIQUES',
   ['technique','severity','host_count','hosts','missing_from']);
 if(!have.length)h+='<div class="dim pad">Nothing is shared between these '+
   'collections - which is itself an answer, and a cleaner one than a table '+
   'of coincidences would have been.</div>';
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
   /* Correlation is only a tab when the export holds more than one
      collection. An empty tab that explains why it is empty is worth having
      where a reader might expect data; in the nav it is just a dead entry. */
   if(v[0]==='correlation'&&!haveCross())return;
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
/* A local model with the case behind it.

   The model is not given the case - it is given the schema and a read-only
   SELECT, and has to go and look, exactly as the MCP server does. That is why
   the steps are shown under every answer: an answer from a 7B is worth what
   the queries behind it are worth, and an analyst who cannot see them has
   been handed a rumour. The page talks to this server and the server talks to
   a model on localhost; nothing leaves the machine. */
/* The Ask panel. A conversation rather than a box, because the second
   question an examiner asks is almost always about the answer to the first -
   "and what else did that address touch" needs an antecedent, and a panel
   that forgets between questions makes the analyst paste the address back in
   every time.

   turns is what is on screen, newest first so the composer stays where it
   was; history is what goes back to the model, and it is only the questions
   and the answers. The tool traffic stays here. */
var ASK={busy:false,q:'',cfg:null,turns:[],history:[],skill:'',need:''};
function askSkill(name){
 var list=(ASK.cfg&&ASK.cfg.skills)||[];
 for(var i=0;i<list.length;i++)if(list[i].name===name)return list[i];
 return null;
}
function viewAsk(){
 var h='<h1>Ask</h1>';
 if(!served)
  return h+'<p class="desc">This needs the investigation server - it is the '+
   'server that talks to the model. Open the case with --serve.</p>';
 if(!ASK.cfg){
  fetch('/api/llm').then(function(r){return r.json();}).then(function(j){
   ASK.cfg=j;draw();}).catch(function(){ASK.cfg={models:[]};draw();});
  return h+'<p class="desc">Looking for a model...</p>';
 }
 var c=ASK.cfg;
 if(!c.models||!c.models.length)
  return h+'<p class="desc">No model answered at <code>'+esc(c.url||'')+
   '</code>. Start one and pull a model that supports tool calling - '+
   '<code>ollama pull llama3.1:8b</code> - then reopen this tab.</p>';
 h+='<p class="desc">A model on this machine, querying this case. It reads '+
    'the tables and nothing else, and every answer shows the queries behind '+
    'it so you can check them.</p>';

 /* The playbooks, as buttons. A skill whose tables this collection does not
    have is still offered, dimmed: it runs, and it reports that the evidence
    is not there, which is a result an examiner needs said rather than left
    to infer from a button that is missing. */
 var sk=c.skills||[];
 if(sk.length){
  h+='<div class="dim" style="margin-top:13px">or run a playbook - the '+
     'sequence an examiner follows, with the tables and the joins already '+
     'named</div><div class="skills">';
  sk.forEach(function(s){
   var thin=!s.has||!s.has.length;
   h+='<button class="skill'+(thin?' thin':'')+'" data-skill="'+esc(s.name)+
      '" title="'+esc(s.about+(thin?' - this case has none of the tables it '+
      'names':''))+'"><b>'+esc(s.title)+'</b>'+
      (s.args&&s.args.length?' <i>needs '+esc(s.args[0].name)+'</i>':'')+
      '</button>';});
  h+='</div>';
 }

 var sel=ASK.skill?askSkill(ASK.skill):null;
 if(sel)
  h+='<div class="askrow"><span class="dim">playbook: <b>'+esc(sel.title)+
     '</b>'+(ASK.need?' - type the '+esc(ASK.need)+' below':'')+
     '</span><button class="mkbtn" id="askclr2">not this one</button></div>';

 h+='<textarea id="askq" placeholder="'+
    (ASK.need?esc('the '+ASK.need+', on its own'):
     'which addresses both failed SSH logins and got a 2xx from the web '+
     'server?')+'">'+esc(ASK.q)+'</textarea>';
 h+='<div class="askrow"><select id="askm">';
 c.models.forEach(function(m){
  h+='<option'+(m===c.model?' selected':'')+'>'+esc(m)+'</option>';});
 h+='</select><button class="mkbtn" id="askgo"'+(ASK.busy?' disabled':'')+'>'+
    (ASK.busy?'thinking...':'ask')+'</button>';
 if(ASK.turns.length)
  h+='<button class="mkbtn" id="askclr">new thread</button>';
 h+='<span class="dim">local · read-only · a 7B on '+
    'CPU takes a minute or two</span></div>';
 if(ASK.turns.length)
  h+='<div class="dim" style="margin-top:6px">'+ASK.turns.length+
     ' exchange'+(ASK.turns.length===1?'':'s')+' in this thread - the model '+
     'sees the last two, so a follow-up can say "it".</div>';

 ASK.turns.forEach(function(t){
  var o=t.out||{};
  h+='<div class="askturn"><div class="askq"><b>'+esc(t.label)+'</b></div>';
  if(o.error)h+='<div class="askans">'+esc(o.error)+'</div>';
  else{
   if(o.unsupported&&o.unsupported.length)
    h+='<div class="askbad"><b>'+o.unsupported.length+' figure'+
       (o.unsupported.length===1?'':'s')+' below appear in no query result:'+
       '</b> '+esc(o.unsupported.join(', '))+'. Those did not come from this '+
       'case. Check the queries yourself before using any of this.</div>';
   h+='<div class="askans">'+esc(o.answer||'(it answered with nothing)')+
      '</div>';
   if(o.truncated)
    h+='<div class="dim" style="margin-top:6px">it used every round it had, '+
       'so this is what it had reached - ask for one part of it, narrower.'+
       '</div>';
   if(o.steps&&o.steps.length){
    h+='<div style="margin-top:11px"><span class="dim">what it looked at, in '+
       'order</span></div>';
    o.steps.forEach(function(st){
     h+='<div class="askstep"><b>'+esc(st.tool)+'</b> '+esc(st.note||'');
     if(st.args&&st.args.sql)
      h+='<div class="asksql">'+esc(st.args.sql)+'</div>';
     h+='</div>';});
   }
   h+='<div class="dim" style="margin-top:9px">answered by '+
      esc(o.model||'')+'</div>';
  }
  h+='</div>';});
 return h;
}
function askRun(name,text){
 if(ASK.busy)return;
 var sel=name?askSkill(name):null;
 var need=sel&&sel.args&&sel.args.length?sel.args[0].name:'';
 if(need&&!text){ASK.skill=name;ASK.need=need;ASK.q='';draw();
  var box=el('askq');if(box)box.focus();return;}
 if(!name&&!text)return;
 var args={};if(need)args[need]=text;
 var label=sel?(sel.title+(text?': '+text:'')):text;
 ASK.busy=true;draw();
 fetch('/api/ask',{method:'POST',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify({question:text,model:(el('askm')||{}).value,
     skill:name||'',args:args,history:ASK.history})})
  .then(function(r){return r.json();})
  .then(function(j){
    ASK.busy=false;ASK.skill='';ASK.need='';ASK.q='';
    /* The server hands back the thread it wants next time. Only replace ours
       when it did - an error carries no history, and dropping the thread on
       a failed question loses the two exchanges before it as well. */
    if(j&&j.history)ASK.history=j.history;
    ASK.turns.unshift({label:label,out:j});draw();})
  .catch(function(e){ASK.busy=false;
    ASK.turns.unshift({label:label,
      out:{error:'the server did not answer: '+e}});draw();});
}
function askWire(){
 var b=el('askgo'),q=el('askq'),clr=el('askclr'),clr2=el('askclr2');
 if(q)q.oninput=function(){ASK.q=q.value;};
 if(q)q.onkeydown=function(e){
  /* Ctrl-Enter sends. Enter has to stay a newline: a question with a quoted
     path or a pasted log line in it is a multi-line question. */
  if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){e.preventDefault();
   askRun(ASK.skill,(q.value||'').trim());}};
 if(clr)clr.onclick=function(){
  ASK.turns=[];ASK.history=[];ASK.skill='';ASK.need='';draw();};
 if(clr2)clr2.onclick=function(){ASK.skill='';ASK.need='';draw();};
 var btns=document.querySelectorAll('.skill');
 for(var i=0;i<btns.length;i++)btns[i].onclick=function(){
  askRun(this.getAttribute('data-skill'),(el('askq')||{}).value||'');};
 if(!b)return;
 b.onclick=function(){askRun(ASK.skill,(q&&q.value||'').trim());};
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
 el('main').innerHTML=st.view==='ask'?viewAsk()
  :st.view==='search'?viewSearch()
  :st.view==='attack'?viewAttack()
  :st.view==='graph'?viewGraph()
  :st.view==='panels'?viewPanels()
  :st.view==='correlation'?viewCorrelation()
  :st.view==='entities'?viewEntities()
  :st.view==='context'?viewContext()
  :st.view==='iocs'?viewIocs()
  :st.view==='marked'?viewMarked():viewOverview();
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
function wireExtras(){
 egWire();
 askWire();
 [].forEach.call(document.querySelectorAll('.gt rect.ev'),function(rc){
  rc.onclick=function(){
   var e=GEV[+rc.getAttribute('data-i')];if(!e||!GSRC)return;
   var entry=mkCycle(GSRC.name,e.row,rowRef(GSRC,e.row,fmtT(e.t)));
   rc.setAttribute('fill',entry&&entry.state?'var(--'+entry.state+')':
     'var(--'+e.s+')');
   rc.setAttribute('opacity',entry&&entry.state==='benign'?.3:
     entry&&entry.state?1:.72);
   rc.setAttribute('width',entry&&entry.state?5:3);};});
 [].forEach.call(document.querySelectorAll('tr.ioc'),function(tr){
  tr.onclick=function(){
   var ind=tr.getAttribute('data-ioc'),key='IOC|'+h32(ind);
   var cur=marks[key],at=-1;
   for(var i=0;i<MK_STATES.length;i++)if(cur&&cur.state===MK_STATES[i][0])at=i;
   var next=at+1>=MK_STATES.length?null:MK_STATES[at+1][0];
   var entry=next?{state:next,note:cur?cur.note||'':'',
                   labels:cur?cur.labels||[]:[]}:null;
   mkSave(key,entry,{table:'IOCS',what:ind});
   tr.className='ioc'+mkClass(entry);};});
 [].forEach.call(document.querySelectorAll('.lbl-chip[data-lbl]'),function(c){
  c.onclick=function(){
   var l=c.getAttribute('data-lbl');st.label=st.label===l?'':l;draw();};});
 /* The case cards are editable in place: a note written somewhere other than
    beside the evidence is a note that will not be written. Saved on blur
    rather than per keystroke - one request per thought, not per letter. */
 [].forEach.call(document.querySelectorAll('textarea[data-note-for]'),function(ta){
  ta.onblur=function(){
   var k=ta.getAttribute('data-note-for'),m=marks[k];if(!m)return;
   if((m.note||'')===ta.value)return;
   m.note=ta.value;mkSave(k,m,m.where);};});
 [].forEach.call(document.querySelectorAll('input[data-lbl-for]'),function(inp){
  inp.onchange=function(){
   var k=inp.getAttribute('data-lbl-for'),m=marks[k];if(!m)return;
   m.labels=inp.value.split(/[ ,;]+/).filter(Boolean);
   mkSave(k,m,m.where);draw();};});
 [].forEach.call(document.querySelectorAll('button[data-cycle]'),function(b){
  b.onclick=function(){
   var k=b.getAttribute('data-cycle'),m=marks[k];if(!m)return;
   var at=-1;
   for(var i=0;i<MK_STATES.length;i++)if(m.state===MK_STATES[i][0])at=i;
   var nx=MK_STATES[(at+1)%MK_STATES.length][0];
   m.state=nx;mkSave(k,m,m.where);draw();};});
 [].forEach.call(document.querySelectorAll('button[data-del]'),function(b){
  b.onclick=function(){
   var k=b.getAttribute('data-del');mkSave(k,null,null);draw();};});
 [].forEach.call(document.querySelectorAll('button[data-ctx]'),function(b){
  b.onclick=function(){ctxOpen(b.getAttribute('data-ctx'),15);};});
 var cg=document.getElementById('ctx_go'),cw=document.getElementById('ctx_when');
 if(cg&&cw){
  var go=function(){
   var v=cw.value.trim();
   if(v)ctxOpen(v,(st.ctx&&st.ctx.minutes)||15);};
  cg.onclick=go;
  cw.onkeydown=function(e){if(e.key==='Enter'){e.preventDefault();go();}};}
 [].forEach.call(document.querySelectorAll('button[data-ctxm]'),function(b){
  b.onclick=function(){
   st.ctx.minutes=+b.getAttribute('data-ctxm');CTX=null;CTXQ=null;draw();};});
 [].forEach.call(document.querySelectorAll('button[data-view]'),function(b){
  b.onclick=function(){loadView(b.getAttribute('data-view'));};});
 var sv=document.getElementById('cs_save');
 if(sv)sv.onclick=function(){
  var n=prompt('Name this view');if(n)saveView(n.trim());};
 var rep=document.getElementById('cs_rep');
 if(rep)rep.onclick=function(){
  var blob=new Blob([caseReport()],{type:'text/markdown'});
  var a=document.createElement('a');
  a.href=URL.createObjectURL(blob);a.download='case-report.md';a.click();};
 var dl=document.getElementById('cs_dl');
 if(dl)dl.onclick=function(){
  var blob=new Blob([JSON.stringify({case:caseInfo,marks:marks},null,1)],
    {type:'application/json'});
  var a=document.createElement('a');
  a.href=URL.createObjectURL(blob);a.download='case.json';a.click();};
 ['cs_name','cs_an'].forEach(function(id){
  var i=document.getElementById(id);if(!i)return;
  i.onchange=function(){
   caseInfo[id==='cs_name'?'name':'examiner']=i.value;
   if(served){try{fetch('/api/case',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify(caseInfo)});}catch(e){}}
  };});
}
function wire(){
 wireExtras();
 wireHisto();
 wireWin();
 [].forEach.call(document.querySelectorAll('[data-open]'),function(b){
  b.onclick=function(){setView('table',b.getAttribute('data-open'));};});
 [].forEach.call(document.querySelectorAll('[data-hostpick]'),function(b){
  b.onclick=function(){setHost(b.getAttribute('data-hostpick'));
                       setView('overview');};});
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
  hostRender();
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
  /* Never while the examiner is typing. The guard listed INPUT and SELECT but
     not TEXTAREA, so writing a note went 'b', 'r', 'u' and then the 't' of
     'brute' fired the focus-the-time-window shortcut and the rest of the word
     was typed into the date box. Any field that takes text has to be here,
     including anything contenteditable. */
  var tg=e.target||{},tn=tg.tagName;
  if(tn==='INPUT'||tn==='SELECT'||tn==='TEXTAREA'||tg.isContentEditable)return;
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
  /* p95, not p90. At p90 one row in ten is wider than its column, which on a
     grid of log lines is a whole screen of clipped text - and the columns
     that suffer are the ones carrying the evidence, because they are the
     ones with the outliers. The extra width costs a little horizontal
     scroll; the missing width costs the reader the message. */
  var p95=lens.length?lens[Math.min(lens.length-1,Math.floor(lens.length*0.95))]:0;
  var chars=Math.max(t.columns[j].length+2,p95);
  /* Short columns keep their content on one line; long ones wrap. The
     threshold sits above a UTC timestamp (19 chars) on purpose - wrapping
     '2026-06-11 12:24:57' onto two lines doubles the height of every row in
     the table for no gain. */
  var nw=(p95<=30&&!num)||(num&&seen);
  /* 7.2px a character was measured against the body font; the monospace
     cells this grid uses for paths and log lines are wider than that, so a
     column of them was sized for text narrower than the text it holds. */
  var px=Math.round(chars*7.9)+20;
  out.push({w:Math.max(64,Math.min(nw?360:620,px)),num:(num&&seen>0),nw:nw});
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
 /* Inside `raw` as well, unlike the window: the timeline chart is drawn raw
    so that picking a spike does not hide the shape it sits in, but choosing a
    collection is a statement about which evidence is in scope at all, and a
    chart still drawn over three hosts would be answering a question nobody
    asked. */
 rows=hostFilter(rows,t);
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
  var r=rows[i];var _m=mkGet(t.name,r);
  h+='<tr data-r="'+i+'" class="'+(r===st.sel?'sel':'')+mkClass(_m)+'">';
  var _st=_m&&_m.state?_m.state:'';
  var _note=_m&&_m.note?_m.note:'';
  h+='<td class="mkc" data-mk="'+i+'" title="'+
     (_st?esc(stateLabel(_st)):'click to mark')+' \u2014 '+
     MK_STATES.map(function(x){return x[1];}).join(' \u203a ')+
     '">'+(_st?MK_GLYPH[_st]:'<span class="g">\u25cb</span>')+'</td>';
  h+='<td class="ntc" data-note="'+i+'" title="'+
     (_note?esc(_note):'add a note')+'">'+
     (_note?'<span class="hasnote">\u270e</span>':
            '<span class="g">\u270e</span>')+'</td>';
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
/* How many rows are put in the DOM, which is not how many the page holds.

   Every row is already here - the export embeds the whole table - so "showing
   the first 500" was never a limit on the evidence, only on what had been
   rendered. Telling the examiner to go and open the CSV to see row 501 of
   their own investigation was the wrong answer to a question the page could
   answer itself.

   The cap stays, because putting a hundred thousand rows into a table element
   locks the tab. It is now the examiner's to raise, per table, and it says
   what raising it will cost. */
var MKW=104,NTW=62;
/* Rows drawn at once. Every one of them is a row the browser lays out on
   each repaint of the grid, and SIGMA_MATCHES carries long rule titles and
   a quoted evidence line per row - a thousand of those is a lot of text to
   measure. Five hundred halves that for every table, and the pager below
   reads its page count from here, so nothing else has to change. */
var PAGE=500, PAGEAT={};
function pageOf(t){return PAGEAT[t.name]||0;}
function pageNote(t,total){
 if(total<=PAGE)return total.toLocaleString()+' row(s)';
 var at=pageOf(t),from=at*PAGE,to=Math.min(total,from+PAGE);
 var pages=Math.ceil(total/PAGE);
 var h='Rows '+(from+1).toLocaleString()+'\u2013'+to.toLocaleString()+
   ' of '+total.toLocaleString()+
   '  <span class="dim">(page '+(at+1)+' of '+pages.toLocaleString()+')</span> ';
 h+='<button class="mkbtn" data-pg="0"'+(at?'':' disabled')+'>\u00ab first</button> ';
 h+='<button class="mkbtn" data-pg="'+(at-1)+'"'+(at?'':' disabled')+
    '>\u2039 prev</button> ';
 h+='<button class="mkbtn" data-pg="'+(at+1)+'"'+(to<total?'':' disabled')+
    '>next \u203a</button> ';
 h+='<button class="mkbtn" data-pg="'+(pages-1)+'"'+(to<total?'':' disabled')+
    '>last \u00bb</button>';
 return h;
}
function wireCap(){
 [].forEach.call(document.querySelectorAll('button[data-pg]'),function(b){
  if(b.disabled)return;
  b.onclick=function(){
   var t=TB[st.table];if(!t)return;
   PAGEAT[t.name]=Math.max(0,+b.getAttribute('data-pg'));
   tRefresh();
   var m=document.getElementById('main');if(m)m.scrollTop=0;};});
}
function tRefresh(){
 var t=TB[st.table];if(!t){return;}
 pvClose();          /* the row it was anchored to may not survive the redraw */
 var rows=tMatching(t);
 var at=pageOf(t)*PAGE;
 if(at>=rows.length)at=PAGEAT[t.name]=0;
 var page=rows.slice(at,at+PAGE);
 var tb=document.getElementById('tb');
 if(tb){tb.innerHTML=tBodyHtml(t,page,page.length);wireRows();}
 TLAST=page;
 var mn=document.getElementById('matchn');
 if(mn){mn.textContent=rows.length.toLocaleString()+' matching';}
 var note=document.getElementById('note');
 if(note){note.innerHTML=pageNote(t,rows.length);wireCap();}
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
 var at=pageOf(t)*PAGE;
 if(at>=rows.length)at=PAGEAT[t.name]=0;
 var page=rows.slice(at,at+PAGE),cap=page.length;
 var h='<h2>'+esc(t.title)+' <span class="badge">'+t.name+'</span></h2>';
 h+='<p class="desc">'+esc(t.description||'');
 if(t.sources&&t.sources.length){h+='<br>sources: '+esc(t.sources.join(', '));}
 h+='</p>';
 h+='<div class="controls"><input type="search" id="q" placeholder="filter rows '+
    'in this table..." value="'+esc(st.tq||'')+'"><span class="badge">'+t.row_count.toLocaleString()+
    ' rows total</span><span class="badge" id="matchn">'+rows.length.toLocaleString()+
    ' matching</span><button class="clr" id="clr">clear filters</button>'+
    hostBadge(t)+winBadge(t);
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
 lay=tLayout(t,page.length?page:rows,Math.max(cap,1));
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
 h+='<table class="tbl" style="width:'+((stretch?avail:total)+MKW+NTW)+
    'px"><colgroup>';
 h+='<col style="width:'+MKW+'px"><col style="width:'+NTW+'px">';
 lay.forEach(function(L,i){
  h+=(stretch&&i===elastic)?'<col>':'<col style="width:'+L.w+'px">';});
 h+='</colgroup><thead><tr id="hdr">'+
    '<th class="mkc" title="click a marker to cycle it through '+
    MK_STATES.map(function(x){return x[1];}).join(' › ')+
    '"><span class="lbl">Analyst mark</span></th>'+
    '<th class="ntc" title="click to write a note beside a row">'+
    '<span class="lbl">Notes</span></th>';
 t.columns.forEach(function(c,i){
  var mark=sortCol===i?(sortAsc?' \\u25b2':' \\u25bc'):'';
  h+='<th data-i="'+i+'" title="'+esc(c)+' \\u2014 click to sort">'+
     '<span class="lbl">'+esc(c)+mark+'</span></th>';});
 h+='</tr><tr class="f" id="frow"><th class="mkc"></th><th class="ntc"></th>';
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
 h+='</tr></thead><tbody id="tb">'+tBodyHtml(t,page,cap)+'</tbody></table>'+lists;
 h+='<div class="empty" id="none"'+(rows.length?' style="display:none"':'')+
    '>'+(rows.length?'No rows match.':emptyNote(t))+'</div>';
 h+='<p class="desc" id="note">'+pageNote(t,rows.length)+'</p>';
 h+='<div id="pvpane"></div>';
 document.getElementById('main').innerHTML=h;
 tWire();
 wireCap();
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
 [].forEach.call(document.querySelectorAll('[data-hostclear]'),function(x){
  x.onclick=function(){setHost('');};});
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
/* ---------- from a finding to the rows underneath it ----------------------
   A Sigma match and a hacktool hit both name the table they came from and
   quote one line of it, shortened to fit a cell. The next question is always
   the same - show me that row where it lives, with the columns the summary
   had to drop and none of them cut short. Clicking the row opens exactly that
   underneath it; the button beside it opens the whole grid, filtered to the
   same row, for the case where the answer is in what surrounds it. */
function evPairs(text){
 /* 'k=v; k=v' back into fragments, keeping each one's raw text so a value
    that was split by mistake can be put back together below. */
 var out=[];
 String(text||'').split('; ').forEach(function(part){
  var i=part.indexOf('=');
  out.push([i<1?'':part.slice(0,i),i<1?'':part.slice(i+1),part]);});
 return out;
}
/* A value can contain '; ' itself - a sudo line quotes the whole command,
   TTY and PWD included - so a fragment whose key is not a column of this
   table is not a field at all. It is the middle of the one before it, and
   joining it back is what stops 'detail' being compared against its own
   first clause, which is a comparison nothing can satisfy.
   Only then is a value tested for the '...' that says it was shortened to
   fit the cell: the shortening can fall in a later fragment, and a value cut
   short must never be matched on - a prefix of a message matches no row. */
function evKeys(t,prs){
 var out=[];
 prs.forEach(function(p){
  var j=t.columns.indexOf(p[0]);
  if(j<0){if(out.length)out[out.length-1][1]+='; '+p[2];return;}
  out.push([j,p[1]]);});
 return out.filter(function(x){return x[1].indexOf('...')<0;});
}
function evSource(t,row){
 var ti=ci(t,'table');
 if(ti<0)return null;
 var name=String(row[ti]||'');
 if(!name||!TB[name]||name===t.name)return null;
 var ev=ci(t,'matched_row'),cx=ci(t,'context'),wi=ci(t,'timestamp_utc');
 return {name:name,
         when:wi>=0?String(row[wi]||''):'',
         pairs:evPairs((ev>=0?row[ev]:'')||(cx>=0?row[cx]:''))};
}
/* null while the table is still being unpacked - the caller says so and the
   decode redraws the page. */
/* TB[name].rows, never T(name). T() unpacks the table it was asked for, and
   unpacking is not cheap: measured on this collection, JOURNAL takes 9.0
   seconds and WEB_LOG 4.2, on the thread that draws the page. A click that
   silently spends nine seconds is the hang this feature was pulled for the
   first time - the click returned in under a millisecond and the freeze
   arrived after it, which is why pre-decoding everything in a test hid it.
   An unpacked table answers instantly; one that is not says so and offers a
   button, so the wait is asked for rather than sprung. */
function evReady(name){
 var t=TB[name];
 return (t&&t.rows!==undefined)?t:null;
}
function evFind(src,cap){
 var t=evReady(src.name);
 if(!t)return null;
 var keys=evKeys(t,src.pairs);
 if(src.when){
  var w=t.columns.indexOf('timestamp_utc');
  if(w>=0)keys.push([w,src.when]);}
 if(!keys.length)return [];
 return evRows(t,keys,cap);
}
/* One column of one table, value -> the rows holding it, built on first use
   and kept. The first version of this had no index and rescanned the table on
   every click; on VAR_LOG that is 1.19M rows walked to show three, and the
   page stopped answering while it happened.
   A single row index is stored as a number and only becomes an array when a
   second row shares the value - most of these columns are near-unique, and a
   million single-element arrays costs more than the table it indexes. */
var IX={};
function ixGet(t,col){
 var key=t.name+'#'+col;
 if(IX[key])return IX[key];
 var m={},rows=t.rows,i,v;
 for(i=0;i<rows.length;i++){
  v=rows[i][col];
  if(v===undefined||v===null||v==='')continue;
  v=String(v);
  if(m[v]===undefined){m[v]=i;}
  else if(typeof m[v]==='number'){m[v]=[m[v],i];}
  else if(m[v].length<64){m[v].push(i);}}
 IX[key]=m;
 return m;
}
/* Rows where every key holds exactly the quoted value.

   The keys are looked up through whichever of them is most likely to be
   near-unique - a timestamp before anything else - so the comparison runs
   over a handful of candidate rows rather than the whole table. Without a
   usable index column it still scans, which is the old behaviour and only
   happens where the summary quoted nothing indexable. */
var IX_PREFER=['timestamp_utc','start_utc','timestamp','client_ip','source_ip',
               'path','pid','command'];
function evRows(t,keys,cap){
 var out=[],i,k,pick=-1,pri=99;
 for(k=0;k<keys.length;k++){
  var nm=t.columns[keys[k][0]],at=IX_PREFER.indexOf(nm);
  if(at<0)at=IX_PREFER.length;               /* usable, just not preferred */
  if(at<pri){pri=at;pick=k;}}
 function ok(r){
  for(var q=0;q<keys.length;q++){
   var v=r[keys[q][0]];
   if(String(v===undefined||v===null?'':v)!==keys[q][1])return false;}
  return true;}
 if(pick>=0){
  var hit=ixGet(t,keys[pick][0])[keys[pick][1]];
  if(hit===undefined)return [];
  var list=(typeof hit==='number')?[hit]:hit;
  for(i=0;i<list.length&&out.length<cap;i++){
   var r1=t.rows[list[i]];
   if(ok(r1))out.push(r1);}
  return out;}
 for(i=0;i<t.rows.length&&out.length<cap;i++){
  if(ok(t.rows[i]))out.push(t.rows[i]);}
 return out;
}
/* What to type into the target grid's filter. The timestamp pins the row it
   came from; without one, the longest thing the summary quoted in full. */
function evQuery(src){
 if(src.when)return src.when;
 var best='';
 src.pairs.forEach(function(p){
  if(p[1].indexOf('...')<0&&p[1].length>best.length&&p[1].length<=60)
   best=p[1];});
 return best;
}
/* One rendering for both pivots, so a row opened from the findings list and
   the same row opened from the Sigma grid read identically. */
function pvRows(name,t,rows){
 var h='';
 rows.forEach(function(r,n){
  h+='<div class="evsrc">'+esc(name)+
     (rows.length>1?' &middot; row '+(n+1)+' of '+rows.length:'')+'</div>';
  h+='<table class="evkv"><tbody>';
  for(var j=0;j<t.columns.length;j++){
   var v=r[j];
   if(v===undefined||v===null||v==='')continue;
   h+='<tr><th>'+esc(t.columns[j])+'</th><td>'+esc(v)+'</td></tr>';}
  h+='</tbody></table>';});
 return h;
}
/* The row as the summary already carries it - no artifact table needed.
   This is what the first attempts kept missing: a Sigma match quotes the
   fields it fired on, and that quote IS the evidence. Reaching past it into
   the artifact table meant unpacking WEB_LOG or JOURNAL - four and nine
   seconds on the thread that draws the page - to show what was already in
   hand. Columns are known before a table is unpacked, so the quote is laid
   out under the artifact's own field names either way.
   Where the table does happen to be unpacked already the full row is shown
   instead, because it carries the fields the quote had to drop. That is a
   bonus when it is free, never something to wait for. */
function pvSummary(name,prs){
 var cols=(TB[name]&&TB[name].columns)||[],out=[];
 prs.forEach(function(p){
  var j=cols.indexOf(p[0]);
  /* the same rejoining evKeys does: a value can contain '; ' itself */
  if(j<0){if(out.length)out[out.length-1][1]+='; '+p[2];return;}
  out.push([p[0],p[1]]);});
 if(!out.length)return '';
 var h='<div class="evsrc">'+esc(name)+'</div><table class="evkv"><tbody>';
 out.forEach(function(kv){
  h+='<tr><th>'+esc(kv[0])+'</th><td>'+esc(kv[1])+'</td></tr>';});
 return h+'</tbody></table>';
}
/* A finding is a summary and the preview under it inherits that: it shows the
   samples the finding kept, not every row the rule matched. Without the line
   ten rows read as the answer when they are ten of nineteen. The Sigma grid
   carries none of this - a row there is one match, and the rest of them are
   the rows around it. */
function pvNote(shown,total){
 if(!total||Number(total)<=shown)
  return '<div class="dim" style="margin-bottom:5px">summary</div>';
 return '<div class="dim" style="margin-bottom:5px">summary - the '+shown+
  ' sample(s) this finding kept, of '+esc(total)+' match(es). Open every '+
  'match of this rule for the rest.</div>';
}
/* Only ever called with rows in hand: an unpacked table that held the row.
   Everything else is drawn from the quote by pvSummary, which needs no table
   at all. */
/* The quote goes up immediately; the whole row replaces it when the server
   answers. The quote is what the summary could fit in a cell - eight fields
   with the long ones shortened - and reading a truncated message is exactly
   what an examiner cannot do. The alternative was unpacking the artifact
   table in the browser, four seconds for WEB_LOG and nine for JOURNAL, which
   is what made a click feel like a hang. The database already holds every
   row, so this is one indexed lookup and a few kilobytes.
   Opened as a file rather than served there is no server to ask, and the
   quote is what there is - which is why it is drawn first and not instead. */
function pvUpgrade(host,name,pairsList){
 if(!served||!host)return;
 var t=TB[name];
 if(!t||!t.columns)return;
 var wanted=pairsList.map(function(prs){
  return evKeys(t,prs).map(function(k){return [t.columns[k[0]],k[1]];});
 }).filter(function(k){return k.length;});
 if(!wanted.length)return;
 Promise.all(wanted.map(function(keys){
  return fetch('/api/find?table='+encodeURIComponent(name)+
               '&keys='+encodeURIComponent(JSON.stringify(keys)))
   .then(function(r){return r.json();})
   .catch(function(){return null;});
 })).then(function(all){
  var cols=null,rows=[];
  all.forEach(function(j){
   if(!j||!j.rows||!j.rows.length)return;
   cols=j.columns;
   rows.push(j.rows[0]);});
  if(!rows.length||!host.parentNode)return;
  host.innerHTML=pvRows(name,{columns:cols},rows);
 });
}
function evHtml(src,rows){
 return pvRows(src.name,TB[src.name],rows);
}
/* The same move from a finding, which cannot be made the same way.
   A Sigma match quotes the row it fired on, field by field, so that row can
   be found again exactly - that is what evKeys does. A finding is a summary
   of many rows ("198 source address(es) with 10+ failed logins") and its
   evidence is written to be read by a person, so there is no row in it to
   reconstruct. What every line of it does carry is an identifier: an address,
   a path, a process name. Those are what the rows underneath are found by, so
   this half is a search and the panel says so rather than implying an
   exactness it does not have. */
var RE_FV_IP=/[0-9]{1,3}(?:[.][0-9]{1,3}){3}/g;
var RE_FV_PATH=/[/][A-Za-z0-9._-]+(?:[/][A-Za-z0-9._-]+)*/g;
var RE_FV_WORD=/[A-Za-z][A-Za-z0-9_.-]{4,}/g;
/* Words that appear in the prose of an evidence line rather than in its
   evidence. Searching for "failure" returns most of an auth log. */
var FV_SKIP=('failure failures against account accounts unnamed success '+
 'accepted publickey password invalid preauth session opened closed user '+
 'users total first last seen mtime size deleted running process processes '+
 'address addresses executable directory directories world-writable').split(' ');
function fvTokens(text){
 var str=String(text||''),out=[],m,i;
 m=str.match(RE_FV_IP);
 if(m)for(i=0;i<m.length;i++)out.push(m[i]);
 m=str.match(RE_FV_PATH);
 if(m)for(i=0;i<m.length;i++){if(m[i].length>4)out.push(m[i]);}
 m=str.match(RE_FV_WORD);
 if(m)for(i=0;i<m.length;i++){
  if(FV_SKIP.indexOf(m[i].toLowerCase())<0)out.push(m[i]);}
 return out;
}
/* Evidence first, the artifact only after it. Both are searched, but ordering
   them by kind across the two - every path before every word - let the
   artifact's own filename outrank the evidence: the dmesg finding spent two
   of its three tries on '/hardware/dmesg.txt', which is where the rows were
   read from and appears in none of them. What a finding quotes is always a
   better identifier than what it was read out of. */
function fvCandidates(evidence,artifact){
 var out=fvTokens(evidence).concat(fvTokens(artifact));
 var seen={},uniq=[];
 out.forEach(function(x){if(!seen[x]){seen[x]=1;uniq.push(x);}});
 /* Three at most. Each one is a pass over every decoded row, and a click has
    to answer while the finger is still on the mouse. */
 return uniq.slice(0,3);
}
/* No search on click any more, and this is the reason the previews had to
   come out the first time: searchAll reads every column of every decoded row,
   and running it - up to three times, once per candidate identifier - froze
   the page for seconds on a collection with VAR_LOG and JOURNAL unpacked.
   A roll-up finding ("198 source address(es) with 10+ failed logins") has no
   single row to open, so there is nothing here worth paying that for. The
   identifier is offered as a button instead: the search view is built to do
   this, it decodes what it needs and it is debounced, so the cost is paid
   deliberately and with the page still answering. */
function fvFind(toks){
 return {token:toks[0]||'',res:[],tried:toks};
}
/* A roll-up finding has no single row to open - "198 source address(es) with
   10+ failed logins" is a count, not a row - but it is not empty either. What
   it carries is its own evidence, written to be read: one line per address,
   per file, per process, with the counts and the span already worked out.
   That is the preview, and it costs nothing to show.
   The first version searched every decoded row for an identifier on each
   click instead, which is what froze the page; the identifier is still
   offered, as a button, so the search happens when it is asked for. */
function fvHtml(got,row,f){
 var h='';
 if(row&&f){
  var det=f.detail>=0?String(row[f.detail]||''):'';
  if(det)h+='<div class="dim" style="margin-bottom:6px">'+esc(det)+'</div>';
  var kept=f.evidence_count>=0?row[f.evidence_count]:0;
  var all=f.count>=0?row[f.count]:0;
  var lines=String(f.evidence>=0?row[f.evidence]||'':'')
            .split(String.fromCharCode(10))
            .filter(function(x){return x.replace(/^[ ]+|[ ]+$/g,'');});
  if(lines.length){
   h+='<div class="evsrc">evidence'+
      (all&&Number(all)>lines.length
       ?' &middot; '+lines.length+' of '+esc(all):'')+'</div>';
   h+='<table class="evkv"><tbody>';
   lines.forEach(function(ln,i){
    h+='<tr><th>'+(i+1)+'</th><td>'+esc(ln)+'</td></tr>';});
   h+='</tbody></table>';}
  else if(!got.token)
   h+='<div class="dim">This finding kept no sample rows.</div>';
 }
 if(got.token)
  h+='<div class="dim" style="margin-top:7px">A roll-up of many rows, so '+
     'there is no single artifact row to open. Search every table for <b>'+
     esc(got.token)+'</b> to see them.</div>';
 return h;
}
/* A finding raised from a Sigma match is not a summary of many rows in the
   way the others are: its artifact is the table name rather than a filename,
   and its evidence is the same 'k=v; k=v' line that SIGMA_MATCHES carries,
   one per kept sample. So it gets the exact treatment - the same evKeys the
   Sigma grid uses - and only a finding that is genuinely a roll-up falls back
   to searching for an identifier. Returns null when there is nothing exact to
   be had, which is what sends the caller to the search. */
function fvExact(row,f){
 var name=String(row[f.artifact]||'');
 if(!name||!TB[name])return null;
 var t=evReady(name);
 var lines=String(row[f.evidence]||'').split(String.fromCharCode(10));
 if(!t){
  /* Nothing unpacked, nothing waited for: every line the finding kept is
     already a quote of the row it came from. */
  var sums=[],k;
  for(k=0;k<lines.length&&sums.length<12;k++){
   var s1=lines[k].replace(/^[ ]+|[ ]+$/g,'');
   if(s1)sums.push(evPairs(s1));}
  if(!sums.length)return null;
  return {name:name,rows:null,sums:sums};}
 /* Every line the finding kept, not the first three. A finding keeps ten
    samples of a rule that may have fired two hundred times, and cutting those
    ten to three hid the only evidence that named the payload. */
 var out=[],when='',i;
 for(i=0;i<lines.length&&out.length<12;i++){
  var ln=lines[i].replace(/^[ ]+|[ ]+$/g,'');
  if(!ln)continue;
  var keys=evKeys(t,evPairs(ln));
  if(!keys.length)continue;
  var hit=evRows(t,keys,1);
  if(hit.length){
   out.push(hit[0]);
   if(!when){
    var w=t.columns.indexOf('timestamp_utc');
    if(w>=0&&hit[0][w])when=String(hit[0][w]);}}}
 if(!out.length)return null;                /* not a quoted row after all */
 return {name:name,rows:out,t:t,when:when};
}
function fvExactHtml(ex,row,f){
 if(ex.rows===null){
  var kept0=ex.sums.length,h0=pvNote(kept0,row[f.count]);
  h0+='<div class="pvbody">';
  ex.sums.forEach(function(p){h0+=pvSummary(ex.name,p);});
  return h0+'</div>';}
 /* A finding keeps ten samples of a rule that may have fired two hundred
    times, so what is below is the evidence this finding carries and not the
    whole of what the rule matched. Say so, and say where the rest is. */
 var kept=String(row[f.evidence]||'').split(String.fromCharCode(10))
          .filter(function(x){return x.replace(/^[ ]+|[ ]+$/g,'');}).length;
 return pvNote(kept,row[f.count])+pvRows(ex.name,ex.t,ex.rows);
}
function fvToggle(tr,t,row){
 var f=fc();
 if(!f)return;
 var ex=fvExact(row,f);
 var got=ex?null:fvFind(fvCandidates(String(row[f.evidence]||''),
                                     String(row[f.artifact]||'')));
 var rule='';
 var b='<div class="evgo">';
 if(ex){
  var ttl=String(row[f.title]||'');
  if(ttl.indexOf('Sigma rule matched: ')===0)rule=ttl.slice(20);
  b+='<button class="mkbtn" data-fvgo="'+esc(ex.name)+'">open '+
     esc(ex.name)+' here</button>';
  if(rule&&TB.SIGMA_MATCHES)
   b+='<button class="mkbtn" data-fvrule="'+esc(rule)+'">every match of '+
      'this rule</button>';
  b+='<span class="dim">the rows this rule fired on, as they are in the '+
     'artifact</span>';
 }else{
  got.res.slice(0,3).forEach(function(R){
   b+='<button class="mkbtn" data-fvgo="'+esc(R.name)+'">open '+
      esc(R.name)+' here</button>';});
  if(got.token)b+='<button class="mkbtn" data-fvall="1">search every table'+
    '</button>';
  b+='<span class="dim">found by identifier, not by exact row - a finding '+
     'summarises many</span>';}
 b+='</div>';
 if(!pvOpen(t.name+'#'+tr.getAttribute('data-r'),
            (ex?fvExactHtml(ex,row,f):fvHtml(got,row,f))+b,tr))return;
 var p=pvPane();
 if(ex&&ex.rows===null)pvUpgrade(p.querySelector('.pvbody'),ex.name,ex.sums);
 var q=ex?(ex.when||''):got.token;
 [].forEach.call(p.querySelectorAll('button[data-fvgo]'),function(x){
  x.onclick=function(e){e.stopPropagation();
   goTable(x.getAttribute('data-fvgo'),q);};});
 var allb=p.querySelector('button[data-fvall]');
 if(allb)allb.onclick=function(e){e.stopPropagation();
  st.gq=got.token;setView('search');};
 var rb=p.querySelector('button[data-fvrule]');
 if(rb)rb.onclick=function(e){e.stopPropagation();
  goTable('SIGMA_MATCHES',rb.getAttribute('data-fvrule'));};
}
/* Only one open at a time. Every open preview is another block the grid has
   to lay out on each repaint, and they were accumulating one per click with
   nothing ever closing them - an examiner working down a list of matches ends
   up with the whole page inside expanded rows. Closing the last one keeps the
   cost of a click flat however many have been opened. */
var PVAT=null;          /* the row the pane is currently showing */
function pvPane(){return document.getElementById('pvpane');}
/* Directly below the row, in the scrolled content rather than the viewport,
   so it stays with its row while the grid is scrolled. */
function pvPlace(tr){
 var p=pvPane(),m=document.querySelector('main');
 if(!p||!m||!tr)return;
 var r=tr.getBoundingClientRect(),mr=m.getBoundingClientRect();
 p.style.top=Math.round(r.bottom-mr.top+m.scrollTop)+'px';
 p.style.left=Math.round(m.scrollLeft)+'px';
 p.style.width=Math.max(320,m.clientWidth-38)+'px';
}
function pvClose(){
 var p=pvPane();
 if(p){p.className='';p.innerHTML='';}
 PVAT=null;
}
/* Draw into the pane. Returns false when the same row is clicked again, so a
   second click closes it exactly as the expanding row used to. */
function pvOpen(key,html,tr){
 var p=pvPane();
 if(!p)return false;
 if(PVAT===key){pvClose();return false;}
 PVAT=key;
 p.className='on';
 pvPlace(tr);
 p.innerHTML='<span class="x" data-pvx="1">&times;</span>'+html;
 var x=p.querySelector('[data-pvx]');
 if(x)x.onclick=function(e){e.stopPropagation();pvClose();};
 return true;
}
function evToggle(tr,t,row,src){
 /* A grid row is one match and says so by being one row - it needs no count
    of the others beside it, and the grid it is already in is where they are.
    The findings preview is the one that summarises, so it carries the note. */
 var found=evFind(src,3);
 var full=!!(found&&found.length);
 /* The same head and the same buttons the findings pane carries. A grid row
    is one match rather than a summary of many, so the line says which of the
    rule's matches this is instead of how many samples were kept - but the
    reader's question is the same one, and so is the way back to the rest. */
 var ri=ci(t,'rule'),cnt=ci(t,'count');
 var rule=ri>=0?String(row[ri]||''):'';
 var total=cnt>=0?row[cnt]:0;
 var head='';
 if(total&&Number(total)>1)
  head='<div class="dim" style="margin-bottom:5px">one of '+esc(total)+
       ' match(es) this rule produced. Open every match of this rule for '+
       'the rest.</div>';
 var html=head+'<div class="pvbody">'+
   (full?evHtml(src,found):pvSummary(src.name,src.pairs))+'</div>'+
   '<div class="evgo">'+
   '<button class="mkbtn" data-evgo="1">open '+esc(src.name)+' here</button>'+
   (rule?'<button class="mkbtn" data-evrule="'+esc(rule)+'">every match of '+
    'this rule</button>':'')+
   '<span class="dim">the row this rule fired on, as it is in the '+
   'artifact</span>'+
   '</div>';
 if(!pvOpen(t.name+'#'+tr.getAttribute('data-r'),html,tr))return;
 var p=pvPane();
 if(!full)pvUpgrade(p.querySelector('.pvbody'),src.name,[src.pairs]);
 var b=p.querySelector('button[data-evgo]');
 if(b)b.onclick=function(e){e.stopPropagation();goTable(src.name,evQuery(src));};
 var rb=p.querySelector('button[data-evrule]');
 if(rb)rb.onclick=function(e){e.stopPropagation();
  goTable(t.name,rb.getAttribute('data-evrule'));};
}
function wireRows(){
 /* The marker is live on every grid, not only the findings: an artifact row
    is exactly the thing an examiner wants to flag, and restricting marking to
    the findings would mean the tool decides what is interesting. */
 [].forEach.call(document.querySelectorAll('td.mkc[data-mk]'),function(td){
  td.onclick=function(ev){
   ev.stopPropagation();
   var t=TB[st.table];if(!t||t.rows===undefined)return;
   var i=+td.getAttribute('data-mk'),row=TLAST[i];if(!row)return;
   var tc=tcols(t),sp=tc.any?rowSpan(tc,row):null;
   var entry=mkCycle(t.name,row,rowRef(t,row,sp?fmtT(sp[0]):''));
   var tr=td.parentNode;
   tr.className=(row===st.sel?'sel':'')+mkClass(entry);
  };});
 /* A note belongs beside the row it is about. Opened in place rather than
    in a dialog: an examiner writing "this is the dropper" wants the row still
    on screen while they type it. Saved on blur, like the case cards. */
 [].forEach.call(document.querySelectorAll('td.ntc[data-note]'),function(td){
  td.onclick=function(ev){
   ev.stopPropagation();
   var t=TB[st.table];if(!t||t.rows===undefined)return;
   var i=+td.getAttribute('data-note'),row=TLAST[i];if(!row)return;
   var tr=td.parentNode,nxt=tr.nextSibling;
   if(nxt&&nxt.className==='noterow'){nxt.parentNode.removeChild(nxt);return;}
   var key=mkKey(t.name,row),m=marks[key];
   var ed=document.createElement('tr');
   ed.className='noterow';
   var td2=document.createElement('td');
   td2.setAttribute('colspan',String(t.columns.length+2));
   td2.innerHTML='<textarea placeholder="why this row matters">'+
     esc(m&&m.note?m.note:'')+'</textarea>'+
     '<div class="hint">saved when you click away \u2014 a note marks the row '+
     'as interesting if it is not marked already</div>';
   ed.appendChild(td2);
   tr.parentNode.insertBefore(ed,tr.nextSibling);
   var ta=td2.querySelector('textarea');ta.focus();
   ta.onblur=function(){
    var cur=marks[key],txt=ta.value.trim();
    if(!cur&&!txt){ed.parentNode&&ed.parentNode.removeChild(ed);return;}
    var tc=tcols(t),sp=tc.any?rowSpan(tc,row):null;
    var entry=cur||{state:'interesting',labels:[]};
    entry.note=txt;
    if(!txt&&!entry.state)entry=null;
    mkSave(key,entry,rowRef(t,row,sp?fmtT(sp[0]):''));
    if(ed.parentNode)ed.parentNode.removeChild(ed);
    tRefresh();};
  };});
 /* Any grid whose rows name another table can be opened. One handler on the
    tbody rather than one per row: the first version asked evSource - which
    splits a row's whole quoted summary - about every rendered row at wiring
    time, and wiring runs again on every page turn and every keystroke in a
    filter box. Five hundred rows of that is work done to answer a question
    nobody asked, since only the row actually clicked is ever opened. */
 (function(){
  var t=TB[st.table];
  if(!t||t.rows===undefined||ci(t,'table')<0)return;
  var body=document.getElementById('tb');
  if(!body)return;
  body.classList.add('pivot');
  body.onclick=function(ev){
   var n=ev.target,tr=null;
   while(n&&n!==body){
    /* the marker and the note pencil own their own clicks */
    if(n.className==='mkc'||n.className==='ntc')return;
    if(n.tagName==='TR'&&n.getAttribute('data-r')!==null)tr=n;
    n=n.parentNode;}
   if(!tr)return;
   var row=TLAST[+tr.getAttribute('data-r')];
   if(!row)return;
   var src=evSource(t,row);
   if(src)evToggle(tr,t,row,src);};
 })();
 if(isView(TB[st.table])!=='findings')return;
 [].forEach.call(document.querySelectorAll('tbody tr[data-r]'),function(tr){
  tr.classList.add('pivot');
  tr.onclick=function(ev){
   /* the marker and the note pencil own their own clicks */
   var n=ev.target;
   while(n&&n!==tr){
    if(n.className==='mkc'||n.className==='ntc')return;
    n=n.parentNode;}
   var t=TB[st.table],row=TLAST[+tr.getAttribute('data-r')];
   if(!t||!row)return;
   st.sel=row;
   var vh=document.getElementById('vhead');
   if(vh){vh.innerHTML=viewHead();wireHead();}
   [].forEach.call(document.querySelectorAll('tbody tr.sel'),function(o){
    o.classList.remove('sel');});
   tr.classList.add('sel');
   fvToggle(tr,t,row);};});
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

/* Marks are loaded before the first paint, so a grid renders already
   coloured rather than flickering into it a moment later. Served, that
   is one request to the case file; opened as a file it is a synchronous
   read of localStorage and the callback runs immediately. */
mkLoad(function(){start();themeInit();});
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
