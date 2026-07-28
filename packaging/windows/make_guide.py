"""Generate the nzbfast Windows getting-started guide PDF."""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

INK = colors.HexColor("#1a1a2e")
ACCENT = colors.HexColor("#2563eb")
CODE_BG = colors.HexColor("#f4f4f5")
CODE_BORDER = colors.HexColor("#d4d4d8")
DIM = colors.HexColor("#52525b")

styles = getSampleStyleSheet()
h1 = ParagraphStyle(
    "H1", parent=styles["Title"], fontSize=22, textColor=INK, spaceAfter=2,
    alignment=0,
)
subtitle = ParagraphStyle(
    "Sub", parent=styles["Normal"], fontSize=11, textColor=DIM, spaceAfter=14,
)
h2 = ParagraphStyle(
    "H2", parent=styles["Heading1"], fontSize=14, textColor=ACCENT,
    spaceBefore=16, spaceAfter=6,
)
body = ParagraphStyle(
    "Body", parent=styles["Normal"], fontSize=10, leading=14, spaceAfter=6,
)
bullet = ParagraphStyle(
    "Bullet", parent=body, leftIndent=14, bulletIndent=4, spaceAfter=3,
)
code = ParagraphStyle(
    "Code", parent=styles["Code"], fontSize=8.5, leading=11.5,
    backColor=CODE_BG, borderColor=CODE_BORDER, borderWidth=0.5,
    borderPadding=6, leftIndent=4, spaceAfter=8, spaceBefore=2,
)
note = ParagraphStyle(
    "Note", parent=body, textColor=DIM, fontSize=9, leading=12,
)


def P(text, style=body):
    return Paragraph(text, style)


def B(text):
    return Paragraph(f"•  {text}", bullet)


def C(text):
    return Preformatted(text, code)


def field_table(rows):
    t = Table(rows, colWidths=[1.35 * inch, 4.9 * inch])
    t.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Courier"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("TEXTCOLOR", (0, 0), (0, -1), ACCENT),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, CODE_BG]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return t


story = [
    P("nzbfast - Getting Started (Windows)", h1),
    P("Early test build · July 2026 · thanks for helping test!", subtitle),
    P(
        "nzbfast is a speed-focused usenet (NZB) downloader: one program "
        "with a live web dashboard. It downloads, verifies, repairs (PAR2) "
        "and unpacks (RAR) automatically. This is the very first Windows "
        "build - it works, but you're among the first to run it on real "
        "Windows hardware, so please report anything strange."
    ),

    P("1. Quick start - just double-click", h2),
    B("Right-click <font face='Courier'>nzbfast-windows-x64.zip</font> → "
      "<b>Extract All</b>, and keep the files together in the extracted "
      "folder (64-bit Windows 10/11)."),
    B("Double-click <b><font face='Courier'>Start nzbfast.bat</font></b>. "
      "That one file does everything - no commands to type."),
    B("<b>If Windows warns you:</b> an “Open File – Security Warning” box → "
      "click <b>Run</b>. If a blue “Windows protected your PC” box appears "
      "instead → click <b>More info</b> then <b>Run anyway</b>. (It's "
      "flagged only because this test build isn't signed.)"),
    B("<b>Firewall:</b> if Windows asks about network access, click "
      "<b>Allow</b> - it's needed for the web dashboard."),
    B("nzbfast then <b>walks you through setup right in the window</b>. If "
      "you don't use SABnzbd, it asks for your provider's address, "
      "username and password (hidden as you type). If you <i>do</i> use "
      "SABnzbd, it offers to use those servers automatically (see §4)."),
    B("<b>Adding more servers is part of the flow</b> - after your first "
      "one it asks if you want to add another (e.g. a backup/block "
      "account). You can also add or remove servers anytime later by "
      "double-clicking the launcher again and choosing “Add another "
      "server”. <b>You never edit a file.</b>"),
    B("It then starts downloading and <b>opens the dashboard in your "
      "browser</b>. To run nzbfast again another day, just double-click "
      "the same launcher."),
    Spacer(1, 4),
    P(
        "That's the whole setup - no files to edit, ever. The launcher "
        "unblocks the files, runs the guided setup, makes the "
        "<font face='Courier'>watch</font> and "
        "<font face='Courier'>downloads</font> folders, and starts "
        "everything. The rest of this guide is reference - you don't need "
        "it to get going.",
        note,
    ),

    P("2. The web dashboard", h2),
    B("On the same PC: open <b><font face='Courier'>http://localhost:6789/"
      "</font></b> in any browser (the launcher opens it for you)."),
    B("From your phone or another machine on your network: "
      "<font face='Courier'>http://&lt;pc-ip&gt;:6789/</font> (find the "
      "PC's IP by running <font face='Courier'>ipconfig</font>)."),
    B("Live speed and per-provider charts, ETA, queue and history, "
      "pause/resume, and a live speed-limit control."),

    P("3. Adding downloads", h2),
    B("<b>Easiest:</b> drop a .nzb file into the "
      "<font face='Courier'>watch</font> folder (inside the nzbfast "
      "folder). It's picked up within a few seconds (the .nzb disappears "
      "once queued - that's normal), downloaded, verified, repaired if "
      "needed, unpacked, and placed in "
      "<font face='Courier'>downloads</font>."),
    B("<b>Sonarr / Radarr:</b> add nzbfast as a <b>SABnzbd</b> download "
      "client - host <font face='Courier'>localhost</font>, port "
      "<font face='Courier'>6789</font>. The API is SABnzbd-compatible."),

    P("4. Already running SABnzbd?", h2),
    P(
        "It just works - and it's easier for you. nzbfast reads your "
        "server details straight out of SABnzbd's own config "
        "(<font face='Courier'>sabnzbd.ini</font>), so the launcher skips "
        "the provider questions entirely. Same servers, logins, connection "
        "counts and backup/block priorities. It only reads that file, "
        "never changes it. The two run side by side (SABnzbd's dashboard is "
        "on port 8080, nzbfast's on 6789). Two things to watch:"
    ),
    B("<b>Your provider caps total connections per account</b>, counted "
      "across every program. If SABnzbd is downloading at the same time, "
      "one of the two may hit “too many connections” errors - easiest is "
      "to pause SABnzbd while trying nzbfast."),
    B("For a fair speed comparison (the whole point of this test!): pause "
      "SABnzbd, then download the same NZB with nzbfast - back-to-back at "
      "the same time of day, since provider speeds drift by the hour."),

    P("5. Running it from a terminal (optional)", h2),
    P(
        "You don't need this - the launcher does it all. But if you prefer "
        "the command line, open a terminal in the folder (click File "
        "Explorer's address bar, type <font face='Courier'>cmd</font>, "
        "press Enter). The interactive setup is the same wizard the "
        "launcher runs, so it's still no-file-editing:"
    ),
    C(
        "nzbfast.exe setup       (add / manage servers, interactive)\n"
        "nzbfast.exe probe       (test the connection)\n"
        "nzbfast.exe serve --watch %USERPROFILE%\\Downloads ^\n"
        "  --out \"%USERPROFILE%\\Downloads\\nzbfast downloads\" --open"
    ),
    P(
        "Useful extra flags on the serve line: "
        "<font face='Courier'>--speedlimit 8M</font> (cap speed), "
        "<font face='Courier'>--apikey secret</font> (use a key of your "
        "own instead of the one nzbfast generates), "
        "<font face='Courier'>--bind 127.0.0.1</font> (serve this PC only; "
        "the default serves every interface), "
        "<font face='Courier'>--port 6789</font> "
        "(change the web port), <font face='Courier'>--mem-limit 2G</font> "
        "(see §6), <font face='Courier'>--quota 100G</font> (daily cap).",
        note,
    ),
    P(
        "First time you run it, nzbfast makes itself an API key and prints "
        "it in the terminal in a box, so the dashboard and the API aren't "
        "open to your whole network. Paste that key into Sonarr/Radarr and "
        "phone apps. It's kept in a file called "
        "<font face='Courier'>apikey</font> next to the config, so you can "
        "read it back later, and it doesn't change on restart. An install "
        "that's already been running is left alone - no key appears under "
        "it. Set <font face='Courier'>NZBFAST_OPEN=1</font> to run with no "
        "key at all.",
        note,
    ),

    P("6. Known quirks of this Windows build", h2),
    B("The <font face='Courier'>--min-free</font> low-disk-space guard is "
      "not active on Windows yet - keep an eye on free space during "
      "big downloads."),
    B("RAM auto-detection isn't wired up on Windows, so the cache budget "
      "defaults to a fixed 1 GB. If you have 16 GB+ of RAM, add "
      "<font face='Courier'>--mem-limit 2G</font> to the serve line for "
      "best speed (edit the launcher, or use the by-hand steps in §5)."),
    B("The dashboard's Resources card (CPU, RAM, disk) will read 0 / stay "
      "flat instead of showing live values on this build - the speed and "
      "per-provider download charts work normally."),
    B("The optional <font face='Courier'>--schedule</font> file runs on UTC "
      "rather than local time."),

    P("7. Something broke?", h2),
    P(
        "Copy the console output (right-click the window's title bar → Edit "
        "→ Select All, then Edit → Copy) and send it over with a note "
        "about what you were doing - that's exactly the feedback this test "
        "build needs. Have fun!"
    ),
]

doc = SimpleDocTemplate(
    "nzbfast-windows-getting-started.pdf",
    pagesize=letter,
    leftMargin=0.9 * inch,
    rightMargin=0.9 * inch,
    topMargin=0.8 * inch,
    bottomMargin=0.8 * inch,
    title="nzbfast - Getting Started on Windows",
    author="nzbfast",
)
doc.build(story)
print("wrote nzbfast-windows-getting-started.pdf")
