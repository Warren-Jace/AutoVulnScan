import argparse
import asyncio
from pprint import pprint

from core.config_loader import load_config
from core.logger import log
from core.orchestrator import Orchestrator


def main():
    """
    Main entry point for the AutoVulnScan application.
    """
    parser = argparse.ArgumentParser(description="AutoVulnScan - Automated Vulnerability Scanner")
    parser.add_argument(
        '-c', '--config-path',
        type=str,
        default='config/vuln_config.yaml',
        help='Path to the YAML configuration file.'
    )
    parser.add_argument(
        '--target-url',
        type=str,
        help='Target URL to scan. Overrides the URL in the config file.'
    )

    args = parser.parse_args()

    try:
        # Load base settings from the config file
        settings = load_config(args.config_path)

        # Override settings with command-line arguments if provided
        if args.target_url:
            settings.target.url = args.target_url
            log.info(f"Overriding target URL with: {settings.target.url}")
        
        log.info("Configuration successfully loaded and processed.")
        log.info("Starting scan with the following settings:")
        
        # Pretty print the final effective configuration
        pprint(settings.model_dump())

        # Instantiate and run the Orchestrator
        orchestrator = Orchestrator(settings)
        asyncio.run(orchestrator.start())

    except Exception as e:
        log.error(f"An error occurred during scanner initialization: {e}")
        # In case of a critical error during setup, exit
        return

if __name__ == "__main__":
    main()
