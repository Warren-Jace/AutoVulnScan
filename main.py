import asyncio
import argparse
from core.config_loader import load_config
from core.orchestrator import Orchestrator
from core.logger import log


async def main():
    parser = argparse.ArgumentParser(description="AutoVulnScan")
    parser.add_argument("url", help="Target URL to scan, this will override the URL in the config file.")
    parser.add_argument("--config", default="config/vuln_config.yaml", help="Path to config file")
    parser.add_argument("--fresh-scan", action="store_true", help="Perform a fresh scan by clearing Redis before starting.")
    args = parser.parse_args()

    try:
        settings = load_config(args.config, url_override=args.url)
        
        # This is a bit of a hack, ideally Pydantic models should be reconstructed
        # But for now, we just modify the object in place.
        if args.fresh_scan:
            settings.advanced.dry_run = True # Re-using dry_run as a flag for fresh scan

        orchestrator = Orchestrator(settings)
        await orchestrator.start()

    except FileNotFoundError:
        log.error(f"Config file not found: {args.config}")
    except Exception as e:
        log.error(f"An error occurred: {e}", exc_info=True)


if __name__ == "__main__":
    asyncio.run(main())
