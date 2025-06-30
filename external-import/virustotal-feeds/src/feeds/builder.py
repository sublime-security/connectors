# -*- coding: utf-8 -*-
"""Livehunt builder module."""
import datetime
import io
import bz2
import logging

import stix2
import vt
from pycti import OpenCTIConnectorHelper

logging.getLogger("plyara").setLevel(logging.ERROR)


class FeedsBuilder:
    """Virustotal Feeds."""

    _SOURCE = "feeds"

    def __init__(
        self,
        client: vt.Client,
        helper: OpenCTIConnectorHelper,
        author: stix2.Identity,
        author_name: str,
        tag: str,
        enabled_feeds: list[str],
    ) -> None:
        """Initialize Virustotal builder."""
        self.client = client
        self.helper = helper
        self.author = author
        self.author_name = author_name
        self.bundle = []
        self.tag = tag
        self.enabled_feeds = enabled_feeds

    def process(self, start_date: str, timestamp: int):
        # Work id will only be set and instantiated if there are bundles to send.

        now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=60)

        for feed_type in self.enabled_feeds:
                
            response = self.client.get(
                f"/feeds/{feed_type}/{now.strftime("%Y%m%d%H%M")}"
            )

            for vtobj in io.BytesIO(bz2.decompress(response.content.read())):

                self.process_json(feed_type, vtobj)

                if len(self.bundle) > 0:
                    if work_id is None:
                        work_id = self.initiate_work(timestamp)
                    self.send_bundle(work_id)

    def process_json(self, feed_type: str, data: dict):
        # TODO: Process each JSON line and insert into opencti
        pass

    def create_indicators_i(self, ioc, external_reference, tags):
        indicator = None
        type_ioc = ""
        if ioc["type"] == "domain":
            type_ioc = "Domain-Name:value"
        elif ioc["type"] == "ip":
            type_ioc = "IPv4-Addr:value"
        elif ioc["type"] == "url":
            type_ioc = "Url:value"
        elif ioc["type"] == "sha256":
            type_ioc = "File:hashes.'SHA-256'"
        elif ioc["type"] == "md5":
            type_ioc = "File:hashes.'MD5'"

        if self.create_indicators:
            if ioc["tags"][0] and ioc["tags"][0] != "":
                indicator = self.helper.api.indicator.create(
                    name=ioc["value"],
                    description="GTI IOC " + ioc["value"],
                    pattern_type="stix",
                    pattern=f"[{type_ioc.lower()} = '" + ioc["value"] + "']",
                    x_opencti_main_observable_type=type_ioc.split(":")[0],
                    objectMarking=[stix2.TLP_GREEN["id"]],
                    objectLabel=tags,
                    value=ioc["value"],
                    valid_from=self.data["Date"],
                    createdBy=self.organization["id"],
                    externalReferences=[external_reference["id"]],
                    update=self.update,
                    indicator_types=["malicious-activity"],
                    x_opencti_score=self.score,
                )
            else:
                indicator = self.helper.api.indicator.create(
                    name=ioc["value"],
                    description="GTI IOC " + ioc["value"],
                    pattern_type="stix",
                    pattern=f"[{type_ioc.lower()} = '" + ioc["value"] + "']",
                    x_opencti_main_observable_type=type_ioc.split(":")[0],
                    objectMarking=[stix2.TLP_GREEN["id"]],
                    value=ioc["value"],
                    valid_from=self.data["Date"],
                    createdBy=self.organization["id"],
                    externalReferences=[external_reference["id"]],
                    update=self.update,
                    indicator_types=["malicious-activity"],
                    x_opencti_score=self.score,
                )
        return indicator

    def send_bundle(self, work_id: str):
        """
        Send the bundle to OpenCTI.

        After being sent, the bundle is reset.

        Parameters
        ----------
        work_id : str
            Work id to use
        """
        self.helper.metric.inc("record_send", len(self.bundle))
        bundle = stix2.Bundle(objects=self.bundle, allow_custom=True)
        self.helper.connector_logger.debug(f"Sending bundle: {bundle}")
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(serialized_bundle, work_id=work_id)
        # Reset the bundle for the next import.
        self.bundle = []

    @staticmethod
    def _compute_score(stats: dict) -> int:
        """
        Compute the score for the observable.

        score = malicious_count / total_count * 100

        Parameters
        ----------
        stats : dict
            Dictionary with counts of each category (e.g. `harmless`, `malicious`, ...)

        Returns
        -------
        int
            Score, in percent, rounded.
        """
        try:
            vt_score = round(
                (
                    stats["malicious"]
                    / (stats["harmless"] + stats["undetected"] + stats["malicious"])
                )
                * 100
            )
        except ZeroDivisionError as e:
            raise ValueError(
                "Cannot compute score. VirusTotal may have no record of the observable"
            ) from e
        return vt_score
