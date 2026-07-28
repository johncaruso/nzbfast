nzbfast - Windows portable build (64-bit)
=========================================

PREFER THE INSTALLER
--------------------
If you downloaded nzbfast-<version>-windows-x64-setup.exe you don't need
this zip: the installer sets up a tray app (no terminal window at all),
a Start Menu entry, optional start-with-Windows, and .nzb double-click
support. This zip is the portable alternative for USB sticks, servers,
and scripted setups.

EASY START (portable zip)
-------------------------
  1. Right-click nzbfast-windows-x64.zip -> Extract All, and keep the
     files together in the extracted folder.
  2. Double-click  "Start nzbfast.bat".
       - If you see "Open File - Security Warning", click Run.
       - If a blue "Windows protected your PC" box appears, click
         "More info" -> "Run anyway".
  3. nzbfast walks you through setup right in the window:
       - If you already use SABnzbd, it offers to use those servers.
       - Otherwise it asks for your usenet provider's address,
         username and password (hidden as you type). You can add
         more servers - e.g. a backup/block account - right there.
  4. It starts downloading and opens the dashboard in your browser
     (http://localhost:6789/). Drop .nzb files into the "watch"
     folder to download them.

You never edit a file. To add or remove a server later, just
double-click the launcher again and choose "Add another server"
or "Remove a server".

To stop nzbfast: press Ctrl+C in its window, or close the window.
To start it again later: double-click "Start nzbfast.bat".

More detail and Sonarr/Radarr setup are in nzbfast-getting-started.pdf.

Everything is built in: RAR extraction and PAR2 verification/repair
are native - no unrar or par2 tool needed, nothing else to install.
