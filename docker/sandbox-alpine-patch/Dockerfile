# Gefunden 19.11.2026 (erster echter Docker-Lauf, docs/ASSUMPTIONS.md A-026): Alpines Standard-
# BusyBox-Build enthaelt KEIN patch-Applet ("sh: patch: not found"). Der Sandbox-Container selbst
# laeuft mit --network none (sandbox.ts), kann also zur Laufzeit nichts nachinstallieren -- deshalb
# ein eigenes, einmal gebautes Image statt einer Annahme ueber ein Stock-Image.
FROM alpine:3.20
RUN apk add --no-cache patch
