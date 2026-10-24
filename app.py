#!/usr/bin/env python3
"""
VulnWatch entrypoint.
Delegates to modular, class-based architecture in src/.
"""

from src import (
    AlertEvaluator,
    Config,
    Database,
    KEVClient,
    MCPServer,
    CVEParser,
    NVDClient,
    TelegramBotListener,
    TelegramNotifier,
    VulnWatchService,
)
from src.main import main

__all__ = [
    "AlertEvaluator",
    "Config",
    "Database",
    "KEVClient",
    "MCPServer",
    "CVEParser",
    "NVDClient",
    "TelegramBotListener",
    "TelegramNotifier",
    "VulnWatchService",
    "main",
]

if __name__ == "__main__":
    main()
