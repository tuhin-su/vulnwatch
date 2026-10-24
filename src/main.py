import logging

from .alerter import AlertEvaluator
from .config import Config
from .database import Database
from .kev import KEVClient
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
    nvd_client = NVDClient(api_key=config.nvd_api_key, base_url=config.nvd_url)
    kev_client = KEVClient(url=config.kev_url)
    telegram_notifier = TelegramNotifier(
        bot_token=config.telegram_bot_token,
        chat_id=config.telegram_chat_id,
        app_name=config.app_name,
    )
    alerter = AlertEvaluator(
        min_cvss=config.min_cvss,
        only_high_or_kev=config.only_high_or_kev,
        max_cve_age_days=config.max_cve_age_days,
    )

    service = VulnWatchService(
        config=config,
        database=database,
        nvd_client=nvd_client,
        kev_client=kev_client,
        telegram_notifier=telegram_notifier,
        alerter=alerter,
    )

    service.run_forever()


if __name__ == "__main__":
    main()
