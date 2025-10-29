# M183_Bruteforce
Überblick
Dieses Projekt demonstriert verschiedene Bruteforce-Angriffe und Verteidigungsmechanismen auf Authentifizierungssysteme innerhalb eines sicheren Testumfelds. Ziel ist es, die typischen Formen von Bruteforce-Attacken praxisnah zu implementieren, Schwachstellen aufzuzeigen und effektive Gegenmassnahmen zu testen.
Das Projekt ist modular aufgebaut und umfasst folgende Hauptbereiche:
•	Angriffe: Mono-, Poly-, Dictionary-, Parallel-, Rainbow-Attacken
•	Verteidigung: Delay-Mechanismen, Counter/Lockout, Captcha, Logging
•	Server-Implementierung: Vulnerable und Secure Server
•	Datenbank und Schema
Projektstruktur
text
attack/
  mono_attack.py           # Einfacher Bruteforce: Ein Alphabet
  poly_attack.py           # Erweiterter Bruteforce: Mehrere Alphabete
  dictionary_attack.py     # Dictionary-based Attack mit Mutationen
  parallel_attack.py       # Parallelisierte Attacke mit Multiprocessing
  rainbow_attack.py        # Rainbow-Table Angriff
  parallel_rainbow_attack.py  # Parallelisierte Rainbow-Table Attacke
db/
  schema.sql               # Datenbank-Definitionen und Logging
  wordlists/               # Passwortlisten für Dictionary-Attacken
defense/
  delay.py                 # Lineare & progressive Verzögerungen
  counter.py               # Login-Versuchsbegrenzung und Lockout
  captcha.py               # reCAPTCHA-Integration
  logging.py               # Authentifizierungsversuch Logging
  defense_wrapper.py       # Konfigurierbare Defense-Presets
server/
  vulnerable_server.py     # Unsicherer Demo-Server
  secure_server.py         # Sicherer Server mit allen Verteidigungen
  create_db.py             # Datenbank-Initialisierung

README.md                  # Diese Dokumentation

Angriffsszenarien (Bruteforce)
Gemäss Bewertungsraster :
Einfach: Verwendung eines einzigen Alphabets (Mono-Attacke). Optionale Erweiterung um Gross-/Kleinschreibung, Zahlen, Sonderzeichen.
Mittel: Nutzung mehrerer Alphabete (Poly-Attacke), inkl. internationalisierter Zeichensätze (Türkisch, Ungarisch, Finnisch, Kyrillisch, Chinesisch, Römisch).
Dictionary: Smart-Vorgehen basierend auf bekannten Benutzerdaten: Permutationen von Namen, Geburtstag und E-Mail-Adressen.
Komplex: Optimierung der Ressourcen durch Parallelisierung oder Rainbow-Tables, verteilte Angriffe auf vorbereitete Hashes.
Angriffe sind in separaten Files und können parametriert werden (z.B. Ziel-URL, Username, Passwortliste).
Verteidigungskonzepte (Gegenmassnahmen)
Einfache Verteidigungen:
Lineare Latenzzeit (Delay nach jedem Versuch, z.B. 0,5–2s)
Progressive Latenzzeit (Exponentiell wachsender Delay je nach Fehlversuchen)
Mittlere Verteidigung:
Counter-Limit: Spezifiziert maximale Fehlversuche, danach Sperrung für definierte Zeit
User-Interaktion: z.B. reCAPTCHA, um Bots abzuwehren
Komplexe Verteidigung:
Logging aller Fehlversuche und Erkennung von Angriffsmustern mit optionaler Alarmierung
Alle Verteidigungen sind in separaten Files modular und parametrierbar integriert
Datenbank
Das Projekt verwendet eine SQLite-Datenbank. Das definierte Schema enthält:
User-Accounts mit Tracking für fehlgeschlagene Versuche und Lockout
Authentifizierungs-Log zur späteren Analyse und Angriffserkennung
Best Practices (Malus-Vermeidung)
Saubere Coding-Standards: Fileheader, Kurzbeschreibung, Aufrufparameter, Autor, Datum, Incode-Kommentare und nachvollziehbare Methodennamen sind in allen relevanten Scripts enthalten.
Versionierung: Vorgegebene Git-Strategie für Teamarbeit und Ausfallsicherheit.
Fehlerhandling: Scripts liefern klare Hinweise bei inkorrektem Aufruf.
Vorbereitung: Fragen zum Code und den Mechanismen können in Fachgesprächen sachgerecht beantwortet werden.
Deployment & Nutzung
Datenbank mit create_db.py initialisieren (Modus: vulnerable/secure/both).
Unsicheren oder sicheren Server starten (je nach Testziel).
Angriffs-Scripts mit den entsprechenden Parametern auf die Server-Endpoint(s) ausführen.
Defense-Einstellungen können per defense_wrapper.py angepasst werden.
Auswertungen erfolgen über das Authentifizierungs-Log und nach Testszenarien gemäss dem Bewertungsraster.
Autoren
Erik Buser (Angriffsscripts & Server)
Cadima Lusiola, Raiyan Mahfuz (Defense und Datenbank)
