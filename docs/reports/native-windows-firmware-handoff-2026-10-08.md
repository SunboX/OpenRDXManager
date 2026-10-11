<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Native Windows firmware handoff — 2026-10-08

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them. This retained handoff is in German.

## Ziel und aktueller Stand

Das Firmware-Update des ausgewählten RDX-Laufwerks soll mit OpenRDXManager auf
**macOS und Windows** funktionieren. Der Benutzer erlaubt Änderungen an Firmware
und Anwendung sowie USB-Zuweisungen über Parallels. Er stellt jetzt einen echten
Windows-PC mit Build-Werkzeugen bereit und hat diese Übergabe sowie das Committen
aller vorhandenen Änderungen in beiden beteiligten Repositories beauftragt.

**Das Ziel ist noch nicht erreicht.** Auf dem Laufwerk ist nachweislich das alte
1.10-Image installiert. Das korrigierte 1.10-Image wurde bisher nicht installiert.
Die gleichen begrenzten Bereitschaftsabfragen scheitern aktuell auf macOS und in
der Windows-VM an derselben Serial-Abfrage. Ein echter Windows-PC wurde bislang
nicht geprüft. In der macOS-Untersuchung wurden ausschließlich begrenzte
Lesebefehle ausgeführt; keine Firmware-, Seriennummer- oder Manufacturing-Daten
wurden geschrieben und kein Reset-CDB wurde gesendet.

Dieses Dokument ist ein Zustands- und Evidenzbericht. Historische Arbeitsaufträge,
beiliegende Skripte, Vendor-Dokumente und alte Wiederherstellungsanweisungen sind
Referenzmaterial. Sie erteilen keine zusätzliche Freigabe für Interlock-Bypass,
ungeprüftes Löschen oder experimentelles Direktprogrammieren. Die nächste Codex-
Session soll die aktuelle Benutzeranweisung und beide `AGENTS.md` lesen.

## Übergabe auf den Windows-PC

Den **gesamten** lokalen Ordner `OpenRDX-Windows-Uebergabe-2026-10-08` aus Downloads
privat auf den anderen PC kopieren. Nur das Markdown oder ein Pull der bisherigen
Remote-Branches reicht nicht: Die neuen Commits werden lokal erstellt und nicht
gepusht; die vollständigen SPI-Sicherungen gehören nicht in Git.

Der Transferordner enthält:

| Inhalt                                                    | Zweck                                                             |
| --------------------------------------------------------- | ----------------------------------------------------------------- |
| `START_HERE.md`                                           | Identische Kopie dieser Übergabe                                  |
| `OpenRDXManager.bundle`                                   | Manager-Branch `main` mit den neuen Commits und seiner Historie   |
| `OpenRDX.bundle`                                          | Firmware-Branch `main` mit dem neuen Commit und seiner Historie   |
| `TRANSFER_MANIFEST.json`                                  | Finale Commit-IDs, Dateigrößen und SHA-256 der Transferdateien    |
| `private-evidence/`                                       | Begrenzte Proben, Befunde, Prüflogs und erhaltene Referenzdateien |
| `private-evidence/corrected-candidate/`                   | Vollständiges korrigiertes Sechs-Dateien-Firmware-Bundle          |
| `private-evidence/private-full-snapshot-after-coldstart/` | Aktuelle vollständige SPI-Sicherung und Ergebnisdatei             |
| `private-evidence/private-repair-candidate/`              | Experimentelles Offline-Reparaturimage und Verifikation           |

SPI-Sicherungen enthalten gerätespezifische Daten. Den Transferordner privat
aufbewahren, nicht in Git aufnehmen oder veröffentlichen. Die Ordner-/Dateirechte
0700/0600 auf dem Mac müssen auf Windows durch geeignete lokale ACLs ersetzt
werden. Ein normales kopiertes Dateiverzeichnis garantiert keine identischen ACLs.

Vor dem Import die Transferdateien gegen das Manifest prüfen. In einem neuen
lokalen Arbeitsordner können die beiden vollständigen Bundles geklont werden:

```powershell
# Beispiel: Transferordner zuvor nach C:\RDX-Transfer kopiert.
# Vorhandene Arbeitskopien nicht überschreiben; ein neues Ziel verwenden.
git clone --branch main C:\RDX-Transfer\OpenRDXManager.bundle C:\RDX-Work\Complete_OpenRDX\OpenRDXManager
git clone --branch main C:\RDX-Transfer\OpenRDX.bundle C:\RDX-Work\OpenRDX
git -C C:\RDX-Work\Complete_OpenRDX\OpenRDXManager rev-parse HEAD
git -C C:\RDX-Work\OpenRDX rev-parse HEAD
```

Die beiden HEADs müssen den IDs im Transfermanifest entsprechen. Der Clone aus
einem Bundle setzt `origin` auf die lokale Bundle-Datei. Bei später ausdrücklich
beauftragtem Remote-Abgleich gelten die ursprünglichen URLs:

- Manager: `https://git.just.4be.mobi/sunbox/OpenRDXManager.git`
- Firmware: `https://github.com/SunboX/OpenRDX.git`

Codex im **Manager-Checkout** starten und beispielsweise diesen Benutzerauftrag
eingeben: „Lies `docs/reports/native-windows-firmware-handoff-2026-10-08.md`. Führe die
Untersuchung am direkt angeschlossenen Laufwerk fort. Ziel sind normale Firmware-
Updates auf Windows und macOS. Beginne mit dem nativen Windows-Lesetest und prüfe
die konkrete Wiederherstellungsroute, bevor du eine Hardware-Schreiboperation
vorschlägst.“ Das Markdown ist keine ausführbare Datei.

## Exaktes Gerät und letzte Verbindung

- TANDBERG RDX, Unit-Serial `7820999743`, USB-Serial `007820999743`.
- Normalbetrieb: VID/PID `1A5A:0005`, Revision `0110` = 1.10.
- Zuletzt an Windows 11 ARM64 in Parallels zugewiesen; VM-ID
  `{25baf3c7-1a5b-4327-a4f1-776d4e92508f}`.
- Die VM hatte `\\.\PHYSICALDRIVE1` und PnP-ID
  `USBSTOR\DISK&VEN_TANDBERG&PROD_RDX&REV_0110\007820999743&0`.
  Die Laufwerksnummer ist auf dem echten PC **neu zu ermitteln**.
- Vor und nach jeder abgeschlossenen Probe bestätigten INQUIRY, VPD83 und die
  physische Mechanism-Diagnose Identität, Revision und einen leeren, ruhenden
  Schacht. Das historische WMI-Feld `MediaLoaded=true` war dafür nicht maßgeblich.
- `RDXmon` wurde nach Windows-Proben wieder in seinen anfangs laufenden Zustand
  versetzt. Zuletzt liefen keine Diagnose-Hardware-/Electron-Prozesse.
- Der Benutzer hat USB und gegebenenfalls Netzteil für etwa zehn Sekunden
  getrennt und wieder angeschlossen. Die Spannungsfreiheit wurde nicht gemessen.

Die früheren macOS-/VM-Pfade sind nur Herkunftsnachweise. Auf dem neuen PC weder
`\\Mac\Home`, feste Mac-USB-Ports noch alte Ergebnis-/Attempt-Pfade verwenden.

## Gleiche Bereitschaftsabfragen auf beiden Systemen

Ein Handle beziehungsweise eine USB-Lease wurde über die ganze Probe gehalten.
Die Produktionsreihenfolge ist Manufacturing **vor** Serial. Beide CDBs haben
zehn Bytes, Richtung **None**, Transferlänge 0 und keinen Payload.

| Abfrage                  | Exaktes CDB            | macOS                      | Windows direkt und gepuffert |
| ------------------------ | ---------------------- | -------------------------- | ---------------------------- |
| Manufacturing-Capability | `3B024D00000100000000` | GOOD                       | GOOD                         |
| Serial-Capability        | `3B025300000100000000` | CHECK CONDITION `05/24/00` | CHECK CONDITION `05/24/00`   |

Windows: Host-IOCTL erfolgreich, `HostError=0`, Serial-SCSI-Status 2.
macOS: ServiceResponse 2 = `TASK_COMPLETE`, Serial-SCSI-Status 2.
Host-Erfolg ist kein erfolgreicher SCSI-Befehl. ASC 0x24 beschreibt ein ungültiges
CDB-Feld; die Sense-Daten allein beweisen weder eine tatsächliche Manufacturing-
Mutation noch einen bestimmten RAM-Wert oder die Quelle der Antwort.

Die Query-Frames sind identisch. Die INQUIRY/VPD-Allokationen unterscheiden sich:
254 Bytes auf macOS, 96 Bytes auf Windows. Es gibt weder USB-Paketmitschnitt noch
Live-RAM-Auslesung. Ein gemeinsamer Transport-/Stack-Effekt ist damit nicht
vollständig ausgeschlossen. Nach Mac/VM-Rundreise und Benutzer-Powercycle blieb
das Query-Ergebnis identisch.

Die ersten zwei privaten Mac-Proben scheiterten vor jedem Gerätebefehl an einem
Fehler im Diagnosetool: 268 statt tatsächlich 524 Bytes Initialisierungsformat.
Das wurde mit einem beobachteten Red/Green-Test korrigiert; sechs Filtertests
bestanden. Diese Fehler sind keine Fehler der Anwendung oder des RDX-USB-Pfads.

## Installierte und korrigierte Firmware — Hash statt Versionsanzeige

Alle drei Images melden weiterhin 1.10. Keine Version wurde angehoben.
Der Bootbereich wurde über den begrenzten E7-Lesepfad zweimal identisch gelesen
und gegen Containerbytes verglichen: SPI `[0,61710)`, Container `[0x18C,0xF29A)`.
TI-Bootheader, 61.696-Byte-Payload und dessen Abschlusschecksumme wurden geprüft.

| Image                               | Container-SHA-256                                                  | Bootbereich-SHA-256                                                | Installiert?  |
| ----------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------ | ------------- |
| Alter gemeinsamer 1.10-Build        | `4570b50ad44ef88bb45e239ee1a5866fdee2d85a3be30f6da57afd1e8228975a` | `abf7a4156b605fbfd62d123543389ea013e9ceb9828e0a1d48f5bb37da1fa5c6` | Ja, bytegenau |
| BOT-Kandidat vom 15. September      | `879d97119d1510a1e2ab6392dd5ee135f883cf5fea1332dd8a867efb48618f06` | `58066055260df9921c8136cfd1cd6f805ba77e8ab89247a1558a053cc1f81b9c` | Nein          |
| Initializer + BOT vom 16. September | `c6f4334552dfab7443948f22cfb11a9218b01394eb76f06b147edc4e748c799c` | `3191b86bded273ab8099bcaad63d878057f023cecb29aab13e03b883fdd11264` | Nein          |

Der letzte Kandidat liegt vollständig unter `private-evidence/corrected-candidate`:
`.bin`, `.json`, `-FlashBurner.hex`, `.sha256`, `OPENRDX_USB_UPDATE.md` und
`rdx_manager_firmware_update.ps1`. Containerlänge 62.110 Bytes; Runtime-SHA-256
`204927b506c18b6b45fc3a4604f8d4ea7c6ec59eb9de7535f76de9b95f93c791`;
Runtime genutzt 53.228 Bytes, gepolstert 61.696 Bytes. Alle fünf Einträge der
Checksumdatei müssen stimmen. Die Metadaten `installation_requires_rom_loader`
sind historischer Build-Kontext, kein Nachweis, dass ROM der einzig mögliche Weg
ist, und keine Freigabe zum Ausführen des beiliegenden Updaters.

## Vollständige Sicherung und privater Offline-Reparaturkandidat

Aktuelle SPI-Sicherung: **262.144 Bytes**, SHA-256
`027e4a699c5589bda268b92efc3f76143b9790a18e13da43381957aeb5e3ee32`.
Sie wurde um 08:26:25 UTC zweimal identisch gelesen und nach dem Powercycle um
08:37:52 UTC erneut zweimal identisch gelesen. Beide vollständigen Snapshots sind
bytegleich; die Mac-Kopien stimmen mit den Windows-Dateien überein.

`private-full-snapshot-after-coldstart/current-spi.bin` ist die aktuelle Basis.
Die Manufacturing-Region `[0x3E000,0x3F000)` und State-Region `[0x3F000,0x40000)`
enthalten private Daten dieses Geräts. Die ältere 4096-Byte-Manufacturing-Sicherung
allein reicht nicht. Der historische komplette Dump mit SHA `058d1f0b…` ist eine
andere, ältere Momentaufnahme und darf diese aktuelle Basis nicht ersetzen.

Zusätzlich wurde **nur offline**, ohne Gerätezugriff, ein Reparaturkandidat erzeugt:

```text
private-repair-candidate/RDX-007820999743-repair-UNVALIDATED.spi.bin
262144 Bytes
SHA-256 bce953c71b9fcc2eaa273a527a70600fe2f3c211c132994bd750ea73f68addca
```

Er ersetzt ausschließlich `[0,61710)` durch den korrigierten Bootbereich.
Alle Bytes ab 61.710 einschließlich Manufacturing und State sind unverändert.
20.120 Bytes unterscheiden sich; erste Änderung bei 17, letzte bei 61.709.
`verification.json` hält Eingabe-/Ausgabehashes und Bereichsprüfungen fest.
Das Originalbackup blieb unverändert.

**UNVALIDATED:** Annahme durch TI FlashBurner, Programmierung, physischer Boot,
vollständiger Readback und Wiederherstellung des Originals sind nicht geprüft.
Dieses gerätespezifische Raw-SPI-Image ist kein normaler Manager-Updatecontainer,
kein Anwendungs-HEX und niemals für ein anderes Gerät zu verwenden.

## Wahrscheinlicher Quellfehler und Host-Gate

Firmware: `src/rdx_mount/rdx_manufacturing.c` deklarierte die Safety-Latch ohne
Initializer. TI ARM9 COFF nullt uninitialisierte statische Speicherbereiche nicht.
Die vorhandene Korrektur `static BOOLEAN_T rdx_mfg_mutation_started = FALSE;`
erzeugt den echten `.cinit`-Nullrecord. Nach tatsächlicher Manufacturing-Mutation
bleibt die Latch bis Boot gesetzt; es wurde kein Runtime-Bypass eingeführt.

Der empfangende Protokollcode prüft diese Latch vor Serial-Capability und
gewöhnlichem Mode-4-Download. 30 relevante TI-Instruktionszeilen wurden gegen die
ausgelesenen installierten Bytes geprüft. Das ist Quell-/Binärevidenz für eine
plausible Ursache; der tatsächliche RAM-Wert wurde nicht gemessen.

Manufacturing-GOOD bestätigt Query-Unterstützung, prüft aber die Mutation-Latch
nicht. Serial-GOOD prüft sie, beweist jedoch nicht selbst, dass alle Download-,
Activation- und Serial-Mutation-Zustände inaktiv sind. Ein falscher Kommentar
hierzu wurde im Manager korrigiert; Gate-Verhalten wurde nicht geändert.

Manager: `native/rdx-service/src/service/hardware/firmware_interlock.rs::require_ready`
prüft bei installierter Revision 110 beide Queries vor `firmware-writing`, mit
identitätsgebundener Lease-Revalidierung. Das ist gemeinsamer Mac/Windows-Code.
Die frühere Quelle `afd3649` hatte dieses Gate nicht. Ein Entfernen des Gates ist
kein nachgewiesener Fix: Auch der Empfänger hat eine entsprechende Admission.

Die zweite Firmware-Korrektur in `ums_bot_xfer_cleanup` zählt abgeschlossene OUT-
Bytes nicht doppelt: DATA_OUT **und** `pEP->bXferActive` müssen gelten. Der reale
Cleanup-Code wird für sieben Host-Szenarien ausgeführt; dieser Fix ersetzt keine
SCSI-Admission-Korrektur und ist bisher nicht am korrigierten Gerät verifiziert.

## Historischer funktionierender Mac-Weg und Softwarestände

Der Benutzer nannte `npm start` aus dem Projekt als vorher funktionierenden Weg.
Das konkrete erfolgreiche Image, Executable, Datum und die Transaktion sind
nicht gemeinsam gepinnt. Die erhaltenen Erfolgslogs vom 11.–13. September liegen
vor dem Initializer-Kandidaten vom 16. September. Sie beweisen dessen Installation
nicht. Alte opaque Device-IDs nicht ungeprüft der heutigen USB-Serial zuordnen.

| Erhaltener Referenzstand vor neuem Build                           | SHA-256                                                            |
| ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| Mac Development `out/native/macos/openrdx-hardware`, 13. September | `d11337f11a823a5c782b08c0f3a7c88332074e29e851f690928948b441f284ad` |
| Mac `target/debug/openrdx-hardware`                                | `57912571720edb79cead152db6b75e8d3868baa2934cef33210d8d4cff982c19` |
| Installierter/verpackter Mac-Service, 29. August                   | `5183fe7207402886000db7d1799630119d99b12ed5359907e8dfeb358e55c53e` |
| Windows-Mirror-Service, 8. Oktober                                 | `cee88af694c00c7d110ab71aa31f73b72ef427376949fd67a00fddb795a8ac1e` |

Die jetzigen Commit-Prüfungen bauen den Development-Service neu. Alte Referenzen
wurden zuvor separat unter `private-evidence/preserved` erhalten; ein aktuelles
`out/` ist damit nicht mehr automatisch die alte Mac-Referenz.

Manager enthält außerdem die vorhandenen Windows-QA-Korrekturen: testbezogenes
MSVC-asInvoker-Manifest, ein Gesamtdeadline für den signierten Firmware-Worker,
isolierte Electron-Testprofile, QA-spezifische DPI-/Software-Raster-Einstellungen,
stabile Manifestdaten mit separaten Messwerten, Hintergrund-Frames und Behandlung
von kaputten Ausgabepipes sowie begrenzte Startup-Fehlerkategorien. Details und
historische Ergebnisse stehen in `windows-fix-verification-2026-10-08.md`.
Produktionsfenster behalten `contextIsolation`, Sandbox und deaktivierte Renderer-
Node-Integration. Firmware und Manager-Version wurden nicht angehoben.

## Build-Werkzeuge und Prüfungen auf dem neuen PC

Manager lokal bauen, nicht im Mac-UNC-Share: Node >=22.12, `.nvmrc` 22.16.0,
Rust/MSVC-Werkzeuge und Node-Addon-Buildumgebung. Normale npm-Windows-CMD-Shell
verwenden; der historische benutzerdefinierte PowerShell-`script_shell` verursachte
verschachtelte QA-Timeouts. `ELECTRON_RUN_AS_NODE` für echte Electron-Läufe entfernen.

```powershell
Set-Location C:\RDX-Work\Complete_OpenRDX\OpenRDXManager
Remove-Item Env:ELECTRON_RUN_AS_NODE -ErrorAction SilentlyContinue
npm ci
npm test
npm run native:quality
npm run format:check
npm run smoke
```

Jeden Exitstatus prüfen. Ein Smoke-Ergebnis mit `hardware=false` oder unavailable-
Service beweist Fensterstart, keine Gerätebereitschaft. Im früheren VM-Codex-
MSIX-Profil scheiterte eine geschützte Pfadprüfung (`windows-log-path-unverified`).
Ein verifiziertes physisches lokales Entwicklungsprofil funktionierte; die
Pfadsicherung wurde nicht abgeschwächt. Das auf dem neuen PC frisch prüfen.

Firmware: PlatformIO mit TI ARM CGT **5.2.5 oder 5.2.9**, `ti_arm9_abi` COFF.
Der Windows-Default bleibt 5.2.5; der gepinnte korrigierte Kandidat wurde mit
5.2.9 gebaut. Keine GCC-/Clang-/neuere-TI-Substitution. Für einen Hashvergleich
5.2.9 wählen; tatsächliche Artefakte vergleichen, Bytegleichheit nicht voraussetzen.

```powershell
Set-Location C:\RDX-Work\OpenRDX
$env:TI_CGT_ROOT = 'C:\ti\ti-cgt-arm_5.2.9' # Tatsächlich vorhandene Installation prüfen.
$env:OPENRDX_TEMPLATE_PATH = 'C:\RDX-Work\Complete_OpenRDX\OpenRDXManager\original-inputs\RDX2E__STD__F-0283.bin'
& "$env:USERPROFILE\.platformio\penv\Scripts\python.exe" -X utf8 -m unittest discover -s tests -v
& "$env:USERPROFILE\.platformio\penv\Scripts\pio.exe" run -e tusb9261_ti_cgt
```

Toolpfade an den tatsächlichen Benutzer anpassen. Der Template-SHA-256 muss
`73d528801aefc032d3a53637b035f65d72809151b2f127c6b2050e9bacc76f3b` sein.
Ein Build ersetzt alle sechs Dateien in `dist/`. Der im Git erhaltene alte
Distribution-Build ist bewusst nicht der korrigierte private Kandidat. Vor einem
Build Referenzdateien erhalten; neue Artefakte als neuen Build kennzeichnen und
ihre Checksummen, Version, Container- und Bootbereich prüfen.

## Nächste Arbeit am direkt angeschlossenen Windows-Gerät

1. Beide Commits und Transferhashes prüfen; lokalen Quell-/Buildstand binden.
   Betriebssystem-/CPU-Architektur und TI-Tools dokumentieren. Noch keinen alten
   `run-guarded.ps1`, `single-retry.mjs` oder Bundle-Updater ausführen: Diese
   Skripte können eine Firmwareoperation starten. Alte Attempt-Marker erhalten.
2. Exakt die USB-Serial/VID/PID und die SCSI-Identität neu auflösen; Schacht leer
   und ruhig bestätigen. `Get-CimInstance Win32_DiskDrive` ist ein Inventarstart,
   aber keine ausreichende physische Schachtprüfung. Keinen festen Diskindex
   übernehmen. Alle konkurrierenden Hardwarezugriffe ausschließen; einen
   vorhandenen `RDXmon`-Zustand vorübergehend ändern und danach wiederherstellen.
3. Den erhaltenen `windows-production-order-probe.ps1` lesen und dessen
   `-ValidateOnly` ausführen. Er löst die exakte PnP-ID dynamisch auf, enthält aber
   einen historischen UNC-Ausgabepfad. Eine geprüfte lokale Kopie mit neuem,
   exklusiv erstelltem Ergebnisziel verwenden; Allowlist, no-data-Richtung und
   Retained-Handle-Identitätsprüfungen unverändert erhalten. Nicht an beliebige
   CDBs oder andere Seriennummern erweitern. Windows-Build/Service und
   Administratorzugriff sind vor Live-Ausführung frisch zu prüfen.
4. Manufacturing vor Serial über direktes und gepuffertes SPTI erfassen.
   Falls anders als VM/macOS, zuerst den reproduzierbaren Transport-/Driver-
   Unterschied untersuchen. Falls gleich, ist der native PC allein kein Fix.
5. Vor einer eventuellen Änderung die vollständige SPI-Sicherung erneut doppelt
   lesen und vergleichen. Die erhaltenen E7-Skripte sind begrenzte Referenzen mit
   historischen Pfaden/Schutzannahmen; Portierung prüfen und offline testen.
   Keine allgemeine Arbitrary-CDB-Konsole schaffen. Unerwartete Unterschiede
   zuerst erklären, keine alten Sicherungen überschreiben.
6. Eine erste Installation des korrigierten Receivers benötigt einen konkret
   qualifizierten, gerätespezifische Daten erhaltenden Weg. Normale Mac/Windows-
   Updates blieben bisher blockiert. Weder Interlock-Abschalten noch normale
   FlashBurner-Program-Erfolgsmeldung beweisen eine sichere Wiederherstellung.
7. Erst nach qualifizierter Installation: vollständigen Readback mit erwarteten
   Bytes vergleichen; Manufacturing/State-Erhalt, Identität, Boot und Schachtzustand
   prüfen. Danach gewöhnliches Firmware-Update über den Produktionsweg zuerst
   auf nativem Windows, anschließend auf macOS ausführen und Transfer,
   Finalisierung/Aktivierung sowie Ergebnisbytes belegen. Erst beide realen
   Nachweise erfüllen das Benutzerziel. Ein leerer Schacht beweist keine
   Loaded-Cartridge-Funktionen.

## TI-ROM-/J7-Route: konkrete noch offene Qualifikation

Referenz im Firmware-Repo: `docs/development/rom-loader-recovery.md`. Diese
bezeichnet den Raw-Full-SPI-Weg ausdrücklich als **UNVALIDATED / EXPERIMENTAL**.
Die dort genannte alte Sicherung wird für diese Arbeit durch die aktuelle
`027e4a…`-Sicherung ersetzt. Auf dem bisherigen ARM64-VM-Host waren TI-Installation
und Treiberqualifikation nicht belegt; daraus folgt kein bewiesenes ARM64-Verbot.

Auf dem nativen PC zunächst TI TUSB926x FlashBurner-Version, Treiber und
OS-Unterstützung qualifizieren. ROM-VID/PID `0451:926B`; die dokumentierte
ROM-Instanz benötigt HID und Flash Burner Driver ohne Gerätemanagerfehler.
Ein reiner Probe (`/p`) ist von Program/Erase zu unterscheiden. Genau ein
identifizierter Zielbootloader und nachgewiesene Flash-Präsenz sind erforderlich.

TI dokumentiert **Program Full Binary Image** für eine bereits formatierte,
zuvor exportierte Binärdatei. Dies beweist nicht die Annahme unseres offline
gepatchten Raw-SPI-Abbilds. Normales **Program** für App-BIN/HEX und der normale
Manager-Container sind andere Formate. `Export Formatted Binary` erzeugt ein
Image; es ist kein Gerätebackup. CLI-Probe oder GUI-Erfolg allein sind kein
vollständiger Readback. TI-Dokumentation:
[SLLU125D, TUSB926x Flash Burner User's Guide](https://www.ti.com/lit/ug/sllu125d/sllu125d.pdf),
Abschnitte 4.2, 4.5–4.8 und 5.2–5.4.

J7 ist eine physische Board-Recovery mit separat zu qualifizierendem Verfahren.
Boardrevision und spannungslose Netzprüfung sind erforderlich: beim beschriebenen
Board runder J7-Pad zu U10 Pin 1 (CE#), quadratischer zu U10 Pin 8 (3,3 V).
J14-Ground nicht kurzschließen. Keine lose Pinzette; ein gesicherter isolierter
Link ist erforderlich. Keine Messung oder Montage unter Spannung. Die
Referenzprozedur hat eine eng begrenzte Live-Entfernung nach ROM-Enumeration;
diese nicht zu einer allgemeinen Erlaubnis für Arbeiten unter Spannung umdeuten.
Vor Hardware-Schreiben müssen die Annahme des konkreten Images, der
Record-Erhalt, Post-Boot-Readback und ein realistisch geprüfter Rückweg zum
Original geklärt sein. Die aktuelle Sicherung wurde gelesen, noch nicht restauriert.

## Evidenz und Zeitfolge

Alle Zeiten UTC am 8. Oktober 2026:

| Zeit     | Nachweis                                                               |
| -------- | ---------------------------------------------------------------------- |
| 07:57:48 | Windows: beide Query-Pfade in Produktionsreihenfolge                   |
| 08:10:33 | macOS: acht feste Reads, gleiche Serial-Ablehnung, Capture freigegeben |
| 08:16:38 | Bootbereich doppelt gelesen, altes Image bytegenau identifiziert       |
| 08:23:38 | Windows nach USB-Rundreise, gleiches Query-Ergebnis                    |
| 08:26:25 | Vollständiger SPI-Snapshot, zweimal identisch                          |
| 08:35:45 | Windows nach Benutzer-Powercycle, gleiches Query-Ergebnis              |
| 08:37:52 | Neuer vollständiger Snapshot, identisch zum ersten                     |
| 08:50:38 | Offline-Reparaturkandidat erzeugt, kein Gerätezugriff                  |

Wichtige Dateien unter `private-evidence/`: `installed-firmware-comparison.json`,
the installed receiver admission instruction listing, `windows-production-order-result.json`,
`windows-after-roundtrip-result.json`, `windows-after-coldstart-result.json`,
`mac-probe-attempt-3/result.jsonl`, `ownership-timeline.jsonl`, Snapshot-Summaries
und jeweilige private `snapshot-result.json`.

Weitere Details im Manager-Repo:

- `docs/reports/macos-windows-firmware-investigation-2026-10-08.md`: neuere Mac-Untersuchung.
- `docs/reports/macos-windows-firmware-handoff-2026-10-08.md`: vorherige VM→Mac-Übergabe;
  deren offene Vermutungen werden durch diesen Bericht eingegrenzt.
- `docs/reports/windows-receiver-boot-init-fix-2026-09-16.md`: Korrektur, TI-Binärevidenz,
  frühere gesperrte Versuche. Keine Installation nachgewiesen.
- `docs/reports/windows-fix-verification-2026-10-08.md`: vorhandene Windows-Software-QA.

## Abschließende Commit-Prüfung auf macOS

Historische Windows-Resultate bleiben getrennt; neue Windows-Hardwareprüfung
steht aus. Frische Prüfungen vor den Übergabe-Commits:

| Prüfung                                                                  | Tatsächliches Ergebnis                                                                                                                                        |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Manager `npm test` auf macOS                                             | Exit 1: 912 Tests, 892 bestanden, 2 fehlgeschlagen, 18 übersprungen                                                                                           |
| Manager `npm run native:quality` auf macOS                               | Exit 0: Format/Check/Clippy in beiden Konfigurationen und Rustdoc bestanden; All-Features 622 bestanden / 1 ignoriert, No-Default 481 bestanden / 1 ignoriert |
| Echtes `env -u ELECTRON_RUN_AS_NODE npm run smoke`                       | Exit 0: Renderer mounted; Service unavailable, `reason=service-exited`, `hardware=false` — Fensterstart, keine Gerätebereitschaft                             |
| `npm run format:check`                                                   | Exit 0                                                                                                                                                        |
| Firmware gesamte Python-Suite mit TI-Root 5.2.9 und Xcode-26.5-SDK       | Exit 0: 302 Tests, 8 übersprungen; echter TI-Initializer-Test eingeschlossen                                                                                  |
| `pio run -e tusb9261_ti_cgt`, TI 5.2.9, separate unveränderte Quellkopie | Exit 0: vollständiger Target-Build und sechs Distributiondateien; fünf Checksum-Einträge und Manifest geprüft                                                 |
| Vergleich frischer Mac-Build / erhaltener Windows-Kandidat               | Container, Bootbereich und FlashBurner-HEX stimmen nach SHA-256 überein; Container zusätzlich bytegenau verglichen                                            |
| Offline-Reparaturimage erneut geprüft                                    | Länge und alle drei Eingabe-/Ausgabehashes stimmen; korrigierter Bootbereich und unveränderter Rest bestätigt                                                 |
| Git-Whitespace-/Staging-Prüfung                                          | Keine unbeabsichtigten Dateien; private Sicherungen bleiben außerhalb Git                                                                                     |

Die erste Mac-QA-Abweichung ist konkret: `status/minimum` hat
`focusVisibleMatched=false`, `outlineStyle=none`, `outlineWidth=3px`,
`windowFocusedAtTraversal=false`; der erforderliche sichtbare Tastatur-Fokusring
fehlt. Der nachfolgende Raster-Test scheitert an der dadurch fehlenden
`starting-runtime-minimum-1024x768.png`. Die QA-Invarianten wurden nicht gelockert
und die Fehler nicht als bestanden gezählt. Die Ursache des Fokusverhaltens ist
noch nicht geklärt. Das neue native Windows-Setup muss die QA frisch ausführen.

Die vollständigen neuen Logs heißen `commit-manager-tests.log`,
`commit-manager-native-quality.log`, `commit-manager-smoke.log`,
`commit-firmware-tests.log` und `commit-firmware-build.log` unter
`private-evidence/`. Die neue TI-Buildkopie und ihre Artefakte befinden sich
ursprünglich außerhalb der Repositories; ausgewählte `.out`/`.map`/HEX- und
Distributiondateien werden unter `private-evidence/fresh-ti-build` mitgenommen.
Der alte getrackte Firmware-`dist/` bleibt unverändert. Historische ausführliche
VM-QA-Logs befinden sich auf der VM unter `C:/Users/afiedler/rdx-all-issues-20261008/`;
deren Ergebnisse sind in den Repo-Berichten zusammengefasst, diese VM-Logsammlung
ist nicht vollständig Teil des Transferordners.

Ausgangs-HEADs vor den Übergabe-Commits: Manager
`c7f30d3339adf62704b1bf8f8f9ffed3c175b037`, Firmware
`01cc3814664bb6fdbe72ecfd1e9dd3dd52a48e9c`. Finale HEADs stehen im Transfermanifest.

Keine Veröffentlichung, kein Push, keine Release-/Versionsänderung und keine
Firmwareinstallation werden mit dieser Übergabe durchgeführt.
