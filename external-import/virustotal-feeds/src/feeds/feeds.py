# -*- coding: utf-8 -*-
"""Virustotal Feeds module."""
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Optional

import vt
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from .builder import FeedsBuilder


class VirustotalFeeds:
    """
    Process Virustotal Feeds
    """

    _DEFAULT_AUTHOR = "Virustotal Feeds"

    # Default run interval
    _CONNECTOR_RUN_INTERVAL_SEC = 60
    _STATE_LATEST_RUN_TIMESTAMP = "latest_run_timestamp"
    # Number of days to load if no state
    _LAST_DAYS_TO_LOAD = 3

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        author = self.helper.api.identity.create(
            name=self._DEFAULT_AUTHOR,
            type="Organization",
            description="Download feeds from Virustotal.",
        )

        # Instantiate vt client from config settings
        api_key = get_config_variable(
            "VIRUSTOTAL_FEEDS_API_KEY",
            ["virustotal_feeds", "api_key"],
            config,
        )
        client = vt.Client(api_key)

        self.interval_sec = get_config_variable(
            "VIRUSTOTAL_FEEDS_INTERVAL_SEC",
            ["virustotal_feeds", "interval_sec"],
            config,
            isNumber=True,
        )

        tag = get_config_variable(
            "VIRUSTOTAL_FEEDS_FILTER_WITH_TAG",
            ["virustotal_feeds", "filter_with_tag"],
            config,
            default="",
        )
        
        enabled_feeds = get_config_variable(
            "VIRUSTOTAL_FEEDS_ENABLED_FEEDS",
            ["virustotal_feeds", "enabled_feeds"],
            config,
            default=["domains","ipaddresses","files","urls"]
        )

        self.builder = FeedsBuilder(
            client,
            self.helper,
            author,
            self._DEFAULT_AUTHOR,
            tag,
            enabled_feeds,
        )

    @staticmethod
    def _current_unix_timestamp() -> int:
        return int(time.time())

    def _get_interval(self) -> int:
        return int(self.interval_sec)

    @staticmethod
    def _get_state_value(
        state: Optional[Mapping[str, Any]], key: str, default: Optional[Any] = None
    ) -> Any:
        if state is not None:
            return state.get(key, default)
        return default

    def _is_scheduled(self, last_run: Optional[int], current_time: int) -> bool:
        if last_run is None:
            self.helper.connector_logger.info(
                "Virustotal Feeds connector clean run"
            )
            return True

        time_diff = current_time - last_run
        return time_diff >= self._get_interval()

    def _get_next_interval(
        self, run_interval: int, timestamp: int, last_run: int
    ) -> int:
        """Get the delay for the next interval."""
        next_run = self._get_interval() - (timestamp - last_run)
        return min(run_interval, next_run)

    def _load_state(self) -> dict[str, Any]:
        current_state = self.helper.get_state()
        if not current_state:
            return {}
        return current_state

    @classmethod
    def _sleep(cls, delay_sec: Optional[int] = None) -> None:
        sleep_delay = (
            delay_sec if delay_sec is not None else cls._CONNECTOR_RUN_INTERVAL_SEC
        )
        time.sleep(sleep_delay)

    def run(self):
        """Run VirustotalFeeds."""
        self.helper.connector_logger.info(
            "Starting Virustotal Feeds Connector..."
        )
        self.helper.metric.state("idle")

        while True:
            self.helper.connector_logger.info(
                "Running Virustotal Feeds connector..."
            )
            run_interval = self._CONNECTOR_RUN_INTERVAL_SEC

            try:
                self.helper.connector_logger.info(
                    f"Connector interval sec: {run_interval}"
                )
                timestamp = self._current_unix_timestamp()
                current_state = self._load_state()
                self.helper.connector_logger.info(
                    f"[Virustotal Feeds] loaded state: {current_state}"
                )

                last_run = self._get_state_value(
                    current_state,
                    self._STATE_LATEST_RUN_TIMESTAMP,
                    int(
                        datetime.timestamp(
                            datetime.fromtimestamp(timestamp)
                            - timedelta(days=self._LAST_DAYS_TO_LOAD)
                        )
                    ),
                )

                if self._is_scheduled(last_run, timestamp):
                    self.helper.metric.inc("run_count")
                    self.helper.metric.state("running")
                    self.helper.connector_logger.info(
                        f"[Virustotal Feeds] starting run at: {current_state}"
                    )
                    new_state = current_state.copy()

                    self.builder.process(last_run, timestamp)

                    # Set the new state
                    new_state[self._STATE_LATEST_RUN_TIMESTAMP] = (
                        self._current_unix_timestamp()
                    )
                    self.helper.connector_logger.info(
                        f"[Virustotal Feeds] Storing new state: {new_state}"
                    )
                    self.helper.set_state(new_state)

                    self.helper.connector_logger.info(
                        "No new Feeds found..."
                    )
                    self.helper.metric.state("idle")
                else:
                    run_interval = self._get_next_interval(
                        run_interval, timestamp, last_run
                    )
                    self.helper.connector_logger.info(
                        f"[Virustotal Feeds] Connector will not run, next run in {run_interval} seconds"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.connector_logger.info(
                    "Virustotal Feeds connector stop"
                )
                sys.exit(0)

            except Exception as e:
                self.helper.metric.inc("error_count")
                self.helper.connector_logger.error(str(e))

            if self.helper.connect_run_and_terminate:
                self.helper.metric.state("stopped")
                self.helper.connector_logger.info("Connector stop")
                self.helper.force_ping()
                sys.exit(0)

            self._sleep(delay_sec=run_interval)


if __name__ == "__main__":
    try:
        vt_feeds = VirustotalFeeds()
        vt_feeds.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
