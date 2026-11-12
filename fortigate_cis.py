#!/usr/bin/env python3
"""Auditoría básica CIS-orientada para FortiGate en laboratorio GNS3.

Solo lectura: no modifica la configuración del dispositivo.
Estos controles seleccionados no representan una certificación CIS completa.
"""

import json
from datetime import datetime
from getpass import getpass
from pathlib import Path

from netmiko import ConnectHandler

FIREWALL_IP = "10.6.94.3"


def extraer_parametros(salida):
    valores = {}
    for linea in salida.splitlines():
        if ":" in linea:
            clave, valor = linea.split(":", 1)
            valores[clave.strip()] = valor.strip()
    return valores


def rango_seguro(valor, minimo, maximo):
    try:
        return minimo <= int(valor) <= maximo
    except (ValueError, TypeError):
        return False


def auditar_fortigate():
    print("\n=== AUDITORÍA INICIAL: FORTIGATE (SOLO LECTURA) ===")
    usuario = input("Usuario SSH [admin]: ").strip() or "admin"
    clave = getpass("Contraseña de FortiGate: ")

    try:
        with ConnectHandler(
            device_type="fortinet",
            host=FIREWALL_IP,
            username=usuario,
            password=clave,
            conn_timeout=30,
            auth_timeout=30,
        ) as conexion:
            salida_global = conexion.send_command(
                "get system global", read_timeout=60
            )
            salida_port1 = conexion.send_command(
                "show system interface port1", read_timeout=30
            )
    except Exception as error:
        print(f"No se pudo completar la auditoría: {type(error).__name__}: {error}")
        return 1

    parametros = extraer_parametros(salida_global)
    acceso = []
    acceso_encontrado = False
    for linea in salida_port1.splitlines():
        linea = linea.strip()
        if linea.startswith("set allowaccess "):
            acceso = linea.split()[2:]
            acceso_encontrado = True

    controles = {
        "SSH versión 1 deshabilitado": parametros.get("admin-ssh-v1") == "disable",
        "Telnet administrativo global deshabilitado": parametros.get("admin-telnet") == "disable",
        "Criptografía fuerte habilitada": parametros.get("strong-crypto") == "enable",
        "Auditoría de comandos CLI habilitada": parametros.get("cli-audit-log") == "enable",
        "HTTP administrativo deshabilitado en port1": acceso_encontrado and "http" not in acceso,
        "Tiempo de inactividad administrativo de 1 a 10 minutos": rango_seguro(
            parametros.get("admintimeout"), 1, 10
        ),
        "Bloqueo administrativo tras 1 a 3 intentos fallidos": rango_seguro(
            parametros.get("admin-lockout-threshold"), 1, 3
        ),
    }

    aprobados = sum(controles.values())
    print("\n--- RESULTADOS ---")
    for control, cumple in controles.items():
        print(f"[{'CUMPLE' if cumple else 'NO CUMPLE'}] {control}")
    print(f"\nTotal: {aprobados}/{len(controles)} controles")

    carpeta = Path(__file__).resolve().parent / "informes"
    carpeta.mkdir(exist_ok=True, parents=True)
    fecha = datetime.now().astimezone()
    destino = carpeta / f"fortigate_auditar_{fecha:%Y%m%d_%H%M%S}.json"
    informe = {
        "dispositivo": "FortiGate",
        "ip": FIREWALL_IP,
        "modo": "auditar",
        "fecha": fecha.isoformat(timespec="seconds"),
        "alcance": "7 controles de laboratorio orientados a hardening; no certificación CIS",
        "controles": controles,
        "aprobados": aprobados,
        "total": len(controles),
    }
    destino.write_text(
        json.dumps(informe, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"Informe guardado en: {destino}")
    return 0


if __name__ == "__main__":
    raise SystemExit(auditar_fortigate())
