"""Generate the nzbfast macOS getting-started guide PDF."""

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
    P("nzbfast - Getting Started (Mac)", h1),
    P("Early test build · July 2026 · thanks for helping test!", subtitle),
    P(
        "nzbfast is a speed-focused usenet (NZB) downloader: one program "
        "with a live web dashboard. It downloads, verifies, repairs (PAR2) "
        "and unpacks (RAR) automatically. This is a universal build - it "
        "runs natively on both Apple Silicon (M1/M2/M3/M4) and Intel Macs. "
        "It's an early test build, so please report anything strange."
    ),

    P("1. Quick start - just double-click", h2),
    B("Double-click <font face='Courier'>nzbfast-mac.zip</font> to unzip "
      "it, and keep the resulting files together in their folder."),
    B("Double-click <b><font face='Courier'>Start nzbfast.command</font></b>. "
      "That one file does everything - no Terminal commands to type."),
    B("<b>The first time</b>, macOS asks whether you're sure (it can't "
      "verify the developer, because this test build isn't signed by "
      "Apple). Click <b>Open</b>. If there's no Open button, go to "
      "<b>System Settings → Privacy &amp; Security</b>, scroll down and "
      "click <b>Open Anyway</b>, then double-click the launcher again."),
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
        "clears Apple's download block, runs the guided setup, makes the "
        "<font face='Courier'>watch</font> and "
        "<font face='Courier'>downloads</font> folders, and starts "
        "everything. The rest of this guide is reference - you don't need "
        "it to get going.",
        note,
    ),

    P("2. The web dashboard", h2),
    B("On the same Mac: open <b><font face='Courier'>http://localhost:6789/"
      "</font></b> in any browser (the launcher opens it for you)."),
    B("From your phone or another machine on your network: "
      "<font face='Courier'>http://&lt;mac-ip&gt;:6789/</font>. Find the "
      "Mac's IP with <font face='Courier'>ipconfig getifaddr en0</font> "
      "(Wi-Fi) or in System Settings → Network."),
    B("Live speed and per-provider charts, ETA, queue and history, "
      "pause/resume, live speed-limit control, and a CPU/RAM/disk "
      "resource chart."),

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
        "(<font face='Courier'>~/Library/Application "
        "Support/SABnzbd/sabnzbd.ini</font>), so the launcher skips the "
        "provider questions entirely. Same servers, logins, connection "
        "counts and backup/block priorities. It only reads that file, "
        "never changes it. The two run side by side (SABnzbd's dashboard "
        "is on port 8080, nzbfast's on 6789). Two things to watch:"
    ),
    B("<b>Your provider caps total connections per account</b>, counted "
      "across every program. If SABnzbd is downloading at the same time, "
      "one of the two may hit “too many connections” errors - easiest is "
      "to pause SABnzbd while trying nzbfast."),
    B("For a fair speed comparison (the whole point of this test!): pause "
      "SABnzbd, then download the same NZB with nzbfast - back-to-back at "
      "the same time of day, since provider speeds drift by the hour."),

    P("5. Running it from Terminal (optional)", h2),
    P(
        "You don't need this - the launcher does it all. But if you like "
        "the command line, right-click the folder in Finder → <b>New "
        "Terminal at Folder</b>, then use these. The interactive setup is "
        "the same wizard the launcher runs, so it's still no-file-editing:"
    ),
    C(
        "./nzbfast setup       # add / manage servers (interactive)\n"
        "./nzbfast probe       # test the connection\n"
        "./nzbfast serve --watch ~/Downloads \\\n"
        "  --out \"$HOME/Downloads/nzbfast downloads\" --open"
    ),
    P(
        "The <font face='Courier'>./</font> is required on the Mac (“run "
        "the program in this folder”). Useful extra flags on the serve "
        "line: <font face='Courier'>--speedlimit 8M</font> (cap speed), "
        "<font face='Courier'>--apikey secret</font> (use a key of your "
        "own instead of the one nzbfast generates), "
        "<font face='Courier'>--bind 127.0.0.1</font> (serve this Mac only; "
        "the default serves every interface), "
        "<font face='Courier'>--port 6789</font> "
        "(change the web port), <font face='Courier'>--quota 100G</font> "
        "(daily cap).",
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

    P("6. Good to know", h2),
    B("This build isn't signed or notarized by Apple (hence the one-time "
      "“Open” prompt) - expected for a test build shared directly, not a "
      "sign anything's wrong."),
    B("It's self-contained: installs nothing, writes only inside its own "
      "folder, and uninstalls by dragging the folder to the Trash."),

    P("7. Something broke?", h2),
    P(
        "Select the text in the nzbfast window (Command-A, then Command-C "
        "to copy) and send it over with a note about what you were doing "
        "- that's exactly the feedback this test build needs. Have fun!"
    ),
]

doc = SimpleDocTemplate(
    "nzbfast-mac-getting-started.pdf",
    pagesize=letter,
    leftMargin=0.9 * inch,
    rightMargin=0.9 * inch,
    topMargin=0.8 * inch,
    bottomMargin=0.8 * inch,
    title="nzbfast - Getting Started on macOS",
    author="nzbfast",
)
doc.build(story)
print("wrote nzbfast-mac-getting-started.pdf")
