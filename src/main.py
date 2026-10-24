import logging

from .alerter import AlertEvaluator
from .bot import TelegramBotListener
from .config import Config
from .database import Database
from .kev import KEVClient
from .mcp_server import MCPServer
from .nvd import NVDClient
from .service import VulnWatchService
from .telegram import TelegramNotifier


def main() -> None:
    config = Config.from_env()

    logging.basicConfig(
        level=config.log_level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    log = logging.getLogger("vulnwatch")
    log.info("Starting %s monitor (poll=%ss, bootstrap=%sh)", config.app_name, config.poll_seconds, config.bootstrap_hours)

    database = Database(db_path=config.db_path)
    database.init_db()

    if config.watchlist:
        for item in config.watchlist.split(","):
            kw = item.strip().lower()
            if kw:
                database.add_to_watchlist(kw)

    nvd_client = NVDClient(api_key=config.nvd_api_key, base_url=config.nvd_url)
    kev_client = KEVClient(url=config.kev_url)
    telegram_notifier = TelegramNotifier(
        bot_token=config.telegram_bot_token,
        chat_id=config.telegram_chat_id,
        app_name=config.app_name,
        enabled=config.telegram_bot_enabled,
    )
    alerter = AlertEvaluator(
        min_cvss=config.min_cvss,
        only_high_or_kev=config.only_high_or_kev,
        max_cve_age_days=config.max_cve_age_days,
        database=database,
        rating_filter=config.rating_filter,
    )

    service = VulnWatchService(
        config=config,
        database=database,
        nvd_client=nvd_client,
        kev_client=kev_client,
        telegram_notifier=telegram_notifier,
        alerter=alerter,
    )

    if config.telegram_bot_enabled:
        bot_listener = TelegramBotListener(
            config=config,
            database=database,
            nvd_client=nvd_client,
            telegram_notifier=telegram_notifier,
        )
        bot_listener.start_in_background()
    else:
        log.info("Telegram bot & notifications disabled (TELEGRAM_BOT_ENABLED=false).")

    if config.mcp_enabled:
        mcp_server = MCPServer(
            config=config,
            database=database,
            nvd_client=nvd_client,
            service=service,
        )
        mcp_server.start_in_background()

    service.run_forever()


if __name__ == "__main__":
    main()
