"""Prints the unified JSON for the HDFC scenario from the assignment brief."""
import asyncio

from app.nlp import load_analyzer
from app.pipeline import Pipeline
from tests.samples import pdf_with_link


async def main() -> None:
    pipeline = Pipeline(load_analyzer())
    files = [("HDFC_Security_Update.pdf", pdf_with_link("http://hdfc-login-update.xyz"))]
    result = await pipeline.run("Security update required", "Please verify your account immediately.", files)
    print(result.model_dump_json(indent=2))
    pipeline.close()


asyncio.run(main())
