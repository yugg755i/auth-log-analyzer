import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = Path(__file__).parent


def render_report(ctx, output_path):
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template("template.html")

    html = template.render(
        ctx=ctx,
        hourly_json=json.dumps(ctx["hourly_histogram"]),
        top_ip_json=json.dumps(ctx["top_ips"]),
    )

    Path(output_path).write_text(html)
    return output_path
