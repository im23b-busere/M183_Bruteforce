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
