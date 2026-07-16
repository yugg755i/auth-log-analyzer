from pathlib import Path


def export_pdf(html_path, pdf_path):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:
        raise RuntimeError(
            "PDF export requires playwright. Install with:\n"
            "  pip install playwright\n"
            "  playwright install chromium"
        ) from e

    html_path = Path(html_path).resolve()
    pdf_path = Path(pdf_path)
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(f"file://{html_path}")
        page.wait_for_timeout(300)
        page.pdf(
            path=str(pdf_path),
            print_background=True,
            format="A4",
            margin={"top": "10mm", "bottom": "10mm", "left": "10mm", "right": "10mm"},
        )
        browser.close()

    return pdf_path
