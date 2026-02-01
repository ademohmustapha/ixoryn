import json
import os
from datetime import datetime
from core.config import Config

def export_report(module, input_data, results):
    output_dir = Config.get("ixoryn.reports.output_directory", "reports")
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.utcnow().isoformat()
    report = {
        "tool": "IXORYN",
        "module": module,
        "timestamp": timestamp,
        "input": input_data,
        "results": results,
    }

    filename = f"{module}_{timestamp.replace(':', '-')}.json"
    path = os.path.join(output_dir, filename)

    with open(path, "w") as f:
        json.dump(report, f, indent=4)

    return path

