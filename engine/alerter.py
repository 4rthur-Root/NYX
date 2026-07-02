class Alerter:
    def send(self, alert: dict) -> None:
        # route selon severity
        if alert["severity"] == "WARNING":
            self._log_warning(alert)
        elif alert["severity"] == "CRITICAL":
            self._log_warning(alert)   # toujours loggué
            self._send_to_soar(alert)  # + envoi SOAR


# json       # stdlib — sérialisation alert.json
#logging    # stdlib — écriture alerts.log
#requests   # si le canal SOAR est HTTP POST


import tempfile, os, json, pathlib

def write_alert(alert: dict, alerts_dir: str) -> None:
    alerts_path = pathlib.Path(alerts_dir)
    alerts_path.mkdir(parents=True, exist_ok=True)
    
    target = alerts_path / f"alert_{alert['alert_id']}.json"
    
    # Écriture atomique — write temp puis rename
    with tempfile.NamedTemporaryFile(
        mode='w', dir=alerts_dir, 
        delete=False, suffix='.tmp'
    ) as f:
        json.dump(alert, f, indent=2)
        tmp_path = f.name
    
    os.rename(tmp_path, target)