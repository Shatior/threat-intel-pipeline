# Fixtures de fuentes

Respuestas reales de cada fuente, capturadas por el workflow `capturar-fixtures`
y reducidas a una selección representativa para los tests sin acceso a red (§14.5).
Se regeneran ejecutando ese workflow; no se editan a mano.

- Fecha de captura: 2026-08-01 (UTC)
- No contienen claves de API, cabeceras de autenticación ni datos personales.

## CISA KEV

- Origen: `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Selección: las 3 primeras entradas del catálogo (catalogVersion `2026.07.29`).
- Registros:
  - `CVE-2026-20316` — Cisco Secure Firewall Management Center (FMC)
  - `CVE-2025-68686` — Fortinet FortiOS
  - `CVE-2026-16812` — Arista VeloCloud Orchestrator

## ThreatFox

- Origen: `POST https://threatfox-api.abuse.ch/api/v1/` con `{"query": "get_iocs", "days": 7}` y cabecera `Auth-Key`.
- Selección: un registro por cada `ioc_type` disponible, para cubrir varios tipos.
- Registros:
  - `id=1866937` `ioc_type=domain` — EtherRAT
  - `id=1866656` `ioc_type=url` — Mozi
  - `id=1866912` `ioc_type=sha256_hash` — Remcos
  - `id=1866893` `ioc_type=md5_hash` — DarkMegi
  - `id=1866938` `ioc_type=ip:port` — Stealc
  - `id=0i` `ioc_type=domain` — registro sintético **inválido** (`confidence_level` fuera de rango), añadido a mano para ejercitar §14.4 (no procede de la API).
  - `id=0t` `ioc_type=sha3_384_hash` — registro sintético de **tipo no soportado** por el esquema, añadido a mano para ejercitar §14.4 (no procede de la API).
