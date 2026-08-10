import demistomock as demisto  # noqa
from CommonServerPython import *  # noqa

from CommonServerUserPython import *  # noqa

""" IMPORTS """

import ast
import csv
import itertools
import logging
import os
import tempfile
import time
import traceback
import uuid
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field, fields
from datetime import datetime
from enum import Enum
from http.client import ResponseNotReady
from typing import (
    Any,
    Callable,
    Generator,
    Iterator,
    Self,
    TypeVar,
)

import requests
from datalake import (
    Atom,
    AtomType,
    BulkSearchFailedError,
    BulkSearchTaskState,
    Datalake,
    DomainAtom,
    EmailAtom,
    FileAtom,
    Hashes,
    IpAtom,
    Output,
    SightingType,
    ThreatType,
    UrlAtom,
    Visibility,
)
from dateutil import parser

requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


""" CONSTANTS """

HIGH_THRESHOLD = 50
LOW_THRESHOLD = 30
POLLING_INTERVAL_SECONDS = 30
TIMEOUT_POLLING_FUNCTIONS_SECONDS = 10800
BULK_SEARCH_INTERVAL_SECONDS = 30
BULK_SEARCH_TIMEOUT_SECONDS = 1800

STATUS_OUTPUTS_PREFIX = "Datalake.status"
SIGHTING_OUTPUTS_PREFIX = "Datalake.Sighting"

PREPROD_URL = "https://ti2.extranet.mrti-center.com/gui/threat"
PROD_URL = "https://datalake.cert.orangecyberdefense.com/gui/threat"

BATCH_SIZE = 200

SUPPORTED_REPUTATION_COMMANDS = (
    "domain",
    "url",
    "ip",
    "email",
    "file",
    "datalake-lookup-hashkey",
    "hashkey",
)

SUPPORTED_SIGHTING_ATOM_TYPES = {
    "IpAtom": IpAtom,
    "DomainAtom": DomainAtom,
    "UrlAtom": UrlAtom,
    "EmailAtom": EmailAtom,
    "FileAtom": FileAtom,
}


DATALAKE_BULK_SEARCH_FIELDS = (
    "atom_type",  # 0
    "atom_value",  # 1
    "events_count",  # 2
    "first_seen",  # 3
    "last_updated",  # 4
    "last_updated_by_source",  # 5
    "sighting_sources",  # 6
    "sources",  # 7
    "sources_for_stix",  # 8
    "threat_entities",  # 9
    "tags",  # 10
    "threat_hashkey",  # 11
    "threat_scores",  # 12
    "threat_types",  # 13,
    ".location.country",  # 14
    ".location.latitude",  # 15
    ".location.longitude",  # 16
    ".hashes.md5",  # 17
    ".hashes.sha1",  # 18
    ".hashes.sha256",  # 19
    ".hashes.sha512",  # 20
    ".filesize",  # 21
    ".filetype",  # 22
    ".hashes.ssdeep",  # 23
    ".filepath",  # 24
    "last_negative_sighting_timestamp",  # 25
    "last_neutral_sighting_timestamp",  # 26
    "last_positive_sighting_timestamp",  # 27
    ".ip_version",  # 28
)

ATOM_TYPE_TO_FEED_INDICATORS_TYPE = {
    "ip": FeedIndicatorType.IP,
    "domain": FeedIndicatorType.Domain,
    "url": FeedIndicatorType.URL,
    "email": FeedIndicatorType.Email,
    "file": FeedIndicatorType.File,
}

HASH_LENGTH_TO_HASH_TYPE = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

DATALAKE_FILE_FIELDS_TO_FILE_FIELDS = (
    ("md5", "MD5"),
    ("sha1", "SHA1"),
    ("sha256", "SHA256"),
    ("sha512", "SHA512"),
    ("filetype", "File"),
    ("ssdeep", "SSDeep"),
    ("filepath", "Path"),
)

T = TypeVar("T")


class Verdict(Enum):
    """Possible verdicts for a Datalake indicator lookup."""

    NOT_FOUND = "Not Found"
    UNSCORED = "Unscored"
    BENIGN = "Benign"
    MALICIOUS = "Malicious"
    SUSPICIOUS = "Suspicious"


""" DATA MODELS """


@dataclass
class NotFoundOutput:
    found: bool | None = None
    atom_type: AtomType | None = None
    status: str | None = None
    indicator: str | None = None
    hashkey: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a dict copy of the object."""
        not_found_dict = self.__dict__.copy()
        if not_found_dict["atom_type"]:
            not_found_dict["atom_type"] = self.atom_type.value

        return not_found_dict


@dataclass
class ContextOutput:
    atom_type: str | None = None
    indicator: str = ""
    system_first_seen: str | None = None
    first_seen: str | None = None
    sources: list[str] = field(default_factory=list)
    scores: dict[str, int] = field(default_factory=dict)
    last_updated: str | None = None
    hashkey: str | None = None
    tags: list[str] = field(default_factory=list)
    threat_entities: list[str] = field(default_factory=list)
    description: str | None = None
    status: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a dict copy of the object."""
        context_output_dict = deepcopy(self.__dict__)
        return context_output_dict


def extract_context_category(scores: list[dict]) -> dict[str, int]:
    """Return a {threat_type: risk_score} mapping from Datalake score entries."""
    return {score_entry["threat_type"]: score_entry["score"]["risk"] for score_entry in scores}


def extract_threat_entities(tags: list[dict]) -> list[str]:
    """Return strings of the form '<Threat Category>: <Threat Entity>', e.g. 'Malware: Cobalt Strike - S0154'."""
    threat_entities: list[str] = []
    for tag in tags:
        for category in tag["categories"]:
            threat_entities.append(f"{category['threat_category']}: {category['threat_entity']}")
    return threat_entities


@dataclass
class ReputationResult:
    threat_found: bool = False
    access_permission: bool | None = None
    threat_details: dict | None = None
    atom_value: str | None = None
    hashkey: str | None = None
    search_phrase: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "ReputationResult":
        valid_keys = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in valid_keys})

    def to_context_output(self) -> ContextOutput:
        """Build the ContextOutput for this reputation result."""
        if self.threat_details is None:
            raise ValueError("Cannot create context output: threat_details is None")

        return ContextOutput(
            atom_type=self.threat_details.get("atom_type"),
            indicator=self.atom_value or "",
            system_first_seen=self.threat_details.get("system_first_seen"),
            first_seen=self.threat_details.get("first_seen"),
            sources=[source["source_id"] for source in self.threat_details.get("sources", [])],
            last_updated=self.threat_details.get("last_updated"),
            hashkey=self.threat_details.get("hashkey"),
            tags=[tag["name"] for tag in self.threat_details.get("tags", [])],
            threat_entities=extract_threat_entities(self.threat_details.get("tags", [])),
            scores=extract_context_category(self.threat_details.get("scores", [])),
        )

    def create_not_found_result(self, client: "DatalakeClient", atom_type: AtomType | None) -> CommandResults:
        """Build CommandResults for a lookup with no matching threat."""
        output = NotFoundOutput(
            found=False,
            atom_type=atom_type,
            status="Not Found",
            indicator=self.atom_value,
            hashkey=self.hashkey,
        )

        indicator_obj = self._create_not_found_indicator_object(self.atom_value, atom_type, client.feed_reliability)

        return CommandResults(
            outputs_prefix=STATUS_OUTPUTS_PREFIX,
            outputs_key_field="indicator",
            readable_output="Did not find entry associated with searched value",
            outputs=output.to_dict(),
            raw_response=output.to_dict(),
            indicator=indicator_obj,
        )

    def create_threat_found_result(self, client: "DatalakeClient") -> CommandResults:
        """Build CommandResults for a lookup that matched a Datalake threat."""
        threat_data = self.threat_details

        output = self.to_context_output()
        output_dict = output.to_dict()

        hashkey = output_dict["hashkey"]

        datalake_url = f"{client.base_threat_url}/{hashkey}"

        risk_level = client.calculate_risk_level(threat_data)

        link_md = f"The Datalake URL: [{datalake_url}]({datalake_url})\n"

        output_dict["status"] = risk_level.value

        output_dict["description"] = self._build_description(
            indicator=self.atom_value,
            status=output_dict["status"],
            scores=output_dict["scores"],
            hashkey=output_dict["hashkey"],
        )

        output_dict["scores"] = ", ".join(f"{k}:{v}" for k, v in output_dict["scores"].items())

        markdown = tableToMarkdown(f"Reputation of {self.atom_value} by Datalake", output_dict)
        markdown = link_md + markdown

        raw_output = output_dict.copy()
        raw_output["found"] = True
        raw_output["datalake_url"] = datalake_url
        raw_output["response_raw"] = threat_data

        indicator_obj = self._create_indicator_object(output, risk_level, threat_data, client.add_tags, client.feed_reliability)

        output_dict["formatted_scores"] = format_datalake_scores(output.scores)

        return CommandResults(
            outputs_prefix=STATUS_OUTPUTS_PREFIX,
            outputs_key_field="indicator",
            readable_output=markdown,
            outputs=output_dict,
            raw_response=raw_output,
            indicator=indicator_obj,
        )

    @staticmethod
    def _create_not_found_indicator_object(
        atom_value: str | None, atom_type: AtomType | None, feed_reliability: str | None
    ) -> Common.Indicator | None:
        """Return a typed Common.Indicator for a not-found result, or None if inputs are missing."""
        if not atom_value or atom_type is None:
            return None

        dbot_score = create_dbot_score_object(atom_value, atom_type, Verdict.NOT_FOUND, feed_reliability)

        if atom_type == AtomType.IP:
            return Common.IP(ip=atom_value, dbot_score=dbot_score)
        if atom_type == AtomType.DOMAIN:
            return Common.Domain(domain=atom_value, dbot_score=dbot_score)
        if atom_type == AtomType.URL:
            return Common.URL(url=atom_value, dbot_score=dbot_score)
        if atom_type == AtomType.FILE:
            return Common.File(name=atom_value, dbot_score=dbot_score)
        if atom_type == AtomType.EMAIL:
            return Common.EMAIL(address=atom_value, dbot_score=dbot_score)  # type: ignore[attr-defined]

        return None

    @staticmethod
    def _create_indicator_object(
        context_output: ContextOutput,
        verdict: Verdict,
        threat_data: dict,
        add_tags: bool = True,
        feed_reliability: str | None = None,
    ) -> Common.Indicator | None:
        """Return a typed Common.Indicator (IP/Domain/URL/File/Email) populated from the threat data."""
        dbot_score = create_dbot_score_object(context_output.indicator, context_output.atom_type, verdict, feed_reliability)
        tags = []
        if add_tags and context_output.tags:
            tags = context_output.tags

        if context_output.atom_type == AtomType.IP.value:
            location = threat_data.get("location") or {}
            return Common.IP(
                ip=context_output.indicator,
                dbot_score=dbot_score,
                tags=tags,
                geo_country=location.get("country"),
                geo_latitude=location.get("latitude"),
                geo_longitude=location.get("longitude"),
            )
        if context_output.atom_type == AtomType.DOMAIN.value:
            return Common.Domain(
                domain=context_output.indicator,
                dbot_score=dbot_score,
                tags=tags,
            )
        if context_output.atom_type == AtomType.URL.value:
            return Common.URL(
                url=context_output.indicator,
                dbot_score=dbot_score,
                tags=tags,
            )
        if context_output.atom_type == AtomType.FILE.value:
            hashes = threat_data.get("hashes") or {}
            return Common.File(
                name=context_output.indicator,
                dbot_score=dbot_score,
                tags=tags,
                md5=hashes.get("md5"),
                sha1=hashes.get("sha1"),
                sha256=hashes.get("sha256"),
                sha512=hashes.get("sha512"),
            )
        if context_output.atom_type == AtomType.EMAIL.value:
            return Common.EMAIL(  # type: ignore[attr-defined]
                address=context_output.indicator,
                dbot_score=dbot_score,
                tags=tags,
            )

        raise DemistoException(f"Atom type '{context_output.atom_type}' is not supported for indicator lookup")

    @staticmethod
    def _build_description(indicator: str, status: str, scores: dict[str, int], hashkey: str | None = None) -> str:
        """Build the human-readable indicator description shown in XSOAR."""
        non_zero = [f"{k}:{v}" for k, v in scores.items() if v > 0]

        if non_zero:
            return (
                "Indicator"
                f" {indicator}"
                f" {f'with hashkey {hashkey} ' if hashkey else ''}analyzed"
                f" by Orange Cyberdefense Datalake; status: {status}."
                f" Flagged categories: {', '.join(non_zero)}."
            )

        return (
            "Indicator"
            f" {indicator} {f'with hashkey {hashkey} ' if hashkey else ''}analyzed"
            f" by Orange Cyberdefense Datalake; status: {status}."
        )


@dataclass
class FeedParameters:
    """Configuration parameters for the feed execution."""

    query_hash: str
    feed_fetch_interval: int
    fetch_lookback: int

    @classmethod
    def from_args(cls, params: dict[str, Any]) -> Self:
        """Build FeedParameters from a demisto.params() dict."""
        return cls(
            query_hash=params.get("queryHash", ""),
            feed_fetch_interval=arg_to_number(params.get("feedFetchInterval", 60)),
            fetch_lookback=arg_to_number(params.get("fetchLookback", 60)),
        )

    def validate(self) -> None:
        """Raise DemistoException if any required parameter is missing or invalid."""
        if not self.query_hash:
            raise DemistoException("Cannot fetch indicators without at least one query hash")

    def get_query_hash_dict(self) -> dict[str, str]:
        """Parse query_hash JSON into a {tag: hash} dict, validating each hash is a UUID."""
        query_hash_dict = json.loads(str(self.query_hash))

        if any(not is_valid_uuid(hash_value) for hash_value in query_hash_dict.values()):
            raise DemistoException("Configured query hashes for indicator fetch are not valid")

        return query_hash_dict

    def get_interval_seconds(self) -> int:
        """Return the fetch interval converted from minutes to seconds."""
        return self.feed_fetch_interval * 60

    def get_lookback_seconds(self) -> int:
        """Return the fetch lookback window converted from minutes to seconds."""
        return self.fetch_lookback * 60


@dataclass
class SubmitSightingsArgs:
    sighting_type: SightingType
    visibility: Visibility
    atoms: list
    atoms_type: list
    count: int = 1
    threat_types: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    start_timestamp: str | None = None
    end_timestamp: str | None = None
    description: str | None = ""
    impersonate_id: str | None = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a dict copy of the object."""
        sight_dict = deepcopy(self.__dict__)

        sight_dict["start_timestamp"] = parser.parse(sight_dict["start_timestamp"])
        sight_dict["end_timestamp"] = parser.parse(sight_dict["end_timestamp"])
        sight_dict["description_visibility"] = sight_dict["visibility"]
        del sight_dict["visibility"]

        if not sight_dict["tags"]:
            del sight_dict["tags"]

        del sight_dict["atoms_type"]

        return sight_dict

    @classmethod
    def from_args(cls, d_args: dict[str, Any]) -> Self:
        """Build SubmitSightingsArgs from a demisto.args() dict."""
        threat_types_list = d_args.get("threat_types", "")

        if threat_types_list != "":
            threat_type_parts = threat_types_list.split(",")
            threat_type_enum_list = list()

            for i in range(0, len(threat_type_parts)):
                threat_type = threat_type_parts[i]
                threat_type_enum_list.append(get_enum_attribute(ThreatType, threat_type))
            threat_types_list = threat_type_enum_list
        tags = d_args.get("tags", "")
        tags_list: list[str] = list(filter(None, tags.replace(" ", "").split(",")))

        atoms = d_args.get("atoms", "")
        atoms_list = atoms.replace(" ", "").split(",")

        atoms_type = d_args.get("atoms_type", "")
        atoms_type_list = atoms_type.replace(" ", "").split(",")

        if len(atoms_list) != len(atoms_type_list):
            raise DemistoException("You did not enter the same number of atoms and atoms_type")

        final_atoms_list = [create_atom(atom_value, atom_type) for atom_value, atom_type in zip(atoms_list, atoms_type_list)]

        visibility = get_enum_attribute(
            Visibility, d_args.get("description_visibility") or d_args.get("visibility", "ORGANIZATION")
        )
        sighting_type = get_enum_attribute(SightingType, d_args["sighting_type"])

        return cls(
            start_timestamp=d_args["start_timestamp"],
            end_timestamp=d_args["end_timestamp"],
            sighting_type=sighting_type,
            visibility=visibility,
            atoms=final_atoms_list,
            atoms_type=atoms_type_list,
            count=int(d_args.get("count", 1)),
            threat_types=threat_types_list,
            tags=tags_list,
            description=d_args.get("description", ""),
            impersonate_id=d_args.get("impersonate_id") or d_args.get("impersonateID") or "",
        )


@dataclass
class ImportIndicatorsArgs:
    output_file_type: str
    polling: bool
    tag: str
    task_id: str
    query_body: dict

    @classmethod
    def from_args(cls, client: "DatalakeClient", args: dict[str, Any]) -> Self:
        """Build ImportIndicatorsArgs from a demisto.args() dict."""
        query_body_raw = args.get("query_body")
        if query_body_raw:
            try:
                query_body = json.loads(query_body_raw)
            except Exception:
                raise DemistoException("'query_body' must be a valid JSON")
        else:
            if not args.get("query_hash"):
                raise DemistoException("Either 'query_body' (JSON) or 'query_hash' must be provided")
            query_body = client.get_qbody_from_qhash(args["query_hash"])

        return cls(
            output_file_type=args["output_file_type"],
            polling=argToBoolean(args.get("polling", False)),
            tag=args.get("tag", ""),
            query_body=query_body,
            task_id=args.get("task_id", ""),
        )


""" CLIENT CLASS """


class DatalakeClient(Datalake):

    def __init__(
        self,
        longterm_token: str,
        env: str = "prod",
        suspicious_threshold: int = LOW_THRESHOLD,
        malicious_threshold: int = HIGH_THRESHOLD,
        log_level: int = logging.CRITICAL,
        proxies: dict | None = None,
        verify: bool = True,
        tlp_color: str | None = None,
        feed_tags: list[str] | None = None,
        add_tags: bool = True,
        feed_reliability: str | None = None,
    ) -> None:
        """Initialize a Datalake client authenticated with a long-term token."""
        self.environment: str = env
        self.permissions: list[dict] | None = None
        self.suspicious_threshold: int = suspicious_threshold
        self.malicious_threshold: int = malicious_threshold
        self.tlp_color: str | None = tlp_color
        self.feed_tags: list[str] = feed_tags or []
        self.add_tags: bool = add_tags
        self.feed_reliability: str | None = feed_reliability
        super().__init__(
            None,
            None,
            longterm_token,
            env,
            log_level,
            proxies,
            verify,
        )

    @property
    def base_threat_url(self) -> str:
        """Return the Datalake GUI base threat URL for the configured environment."""
        return PREPROD_URL if self.environment == "preprod" else PROD_URL

    def has_permission(self, permission_name: str) -> bool:
        """Check whether the Datalake account used by the client has a specific permission."""
        if self.permissions is None:
            info = self.MyAccount.me()
            self.permissions = info["role"]["administration_permissions"]
        for p in self.permissions:
            if p["name"] == permission_name:
                return True
        return False

    def get_verdict_from_max_score(self, max_score: int | None) -> Verdict:
        """Map a max risk score to a Verdict using the client's thresholds."""
        if max_score is None:
            return Verdict.UNSCORED
        if max_score <= self.suspicious_threshold:
            return Verdict.BENIGN
        if max_score <= self.malicious_threshold:
            return Verdict.SUSPICIOUS
        return Verdict.MALICIOUS

    def calculate_risk_level(self, data: dict) -> Verdict:
        """Return the Verdict for a threat dict by taking the max risk across its scores."""
        scores = data.get("scores", [])
        if not scores:
            return self.get_verdict_from_max_score(None)
        return self.get_verdict_from_max_score(max(score["score"]["risk"] for score in scores))

    def check(self, atom_type: AtomType, atom_value: list[str]) -> list[ReputationResult]:
        """Bulk-lookup atom values of a given type and return one ReputationResult per input."""
        bulk_items: list[ReputationResult] = []
        results = self.Threats.bulk_lookup(
            atom_values=atom_value,
            atom_type=atom_type,
            hashkey_only=False,
            output=Output.JSON,
        )[atom_type.value]

        for result in results:
            if not result["threat_found"] or not result.get("threat_details"):
                bulk_item = ReputationResult(atom_value=result["search_phrase"])
                bulk_items.append(bulk_item)
                continue
            result["threat_details"] = DatalakeClient._prepare_threat_data_dto(result["threat_details"])
            bulk_items.append(ReputationResult.from_dict(result))

        return bulk_items

    def check_hashkey(self, hashkeys: list[str]) -> list[ReputationResult]:
        """Fetch threat data for the given hashkeys and return one ReputationResult per input."""
        list_threats, _ = self.Threats.get_threats_with_comments(hashkeys)
        threat_by_hashkey = {t["hashkey"]: DatalakeClient._prepare_threat_data_dto(t) for t in list_threats["results"]}

        results: list[ReputationResult] = []
        for hashkey in hashkeys:
            threat_data = threat_by_hashkey.get(hashkey)
            if threat_data is None:
                results.append(ReputationResult(hashkey=hashkey, atom_value=hashkey))
            else:
                atom_value = get_atom_value_by_atom_type(threat_data["content"], threat_data["atom_type"])
                results.append(
                    ReputationResult(
                        threat_found=True,
                        threat_details=threat_data,
                        atom_value=atom_value,
                        hashkey=threat_data["hashkey"],
                    )
                )
        return results

    def get_qbody_from_qhash(self, qhash: str) -> dict:
        """Resolve a query hash to its query body via the AdvancedSearch API."""
        adv_search = self.AdvancedSearch.advanced_search_from_query_hash(qhash, limit=0)
        return adv_search["query_body"]

    @contextmanager
    def download_bulk_task(self, task: Any, output_type: str) -> Generator[str | None, None, None]:
        """Context manager: attempt to download a ready bulk search task to a temp file.

        Yields the filepath on success, or None if the task is not ready yet (ResponseNotReady).
        The temp file is always deleted on exit.
        """
        filepath = _generate_output_path()
        try:
            o = get_enum_attribute(Output, output_type)
            is_stream = output_type == "CSV"
            try:
                result = task.download(output=o, stream=is_stream)
            except ResponseNotReady:
                yield None
                return

            if is_stream:
                write_http_stream_to_file(filepath, result)
            else:
                with open(filepath, "w") as f:
                    json.dump(result, f)

            yield filepath
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

    def create_bulk_task(self, q_body: dict, timelimit: int | None = None) -> Any:
        """Create a Datalake bulk-search task and appends a system_last_updated time filter when possible."""
        if timelimit and len(q_body.keys()) > 0 and list(q_body.keys())[0] == "AND":
            q_body["AND"].append(
                {
                    "AND": [
                        {
                            "field": "system_last_updated",
                            "type": "filter",
                            "value": timelimit,
                        }
                    ]
                }
            )

        try:
            return self.BulkSearch.create_task(query_fields=DATALAKE_BULK_SEARCH_FIELDS, query_body=q_body)
        except ValueError as e:
            raise DemistoException(f"Invalid Datalake Query Body: {str(e)}")

    @staticmethod
    def _prepare_threat_data_dto(data: dict) -> dict:
        """Whitelist known fields and lift nested location/hashes to the top level."""
        known_fields = {
            "content",
            "comments",
            "first_seen",
            "hashkey",
            "access_permission",
            "atom_type",
            "last_updated",
            "last_neutral_sighting_timestamp",
            "last_positive_sighting_timestamp",
            "last_negative_sighting_timestamp",
            "last_updated_by_source",
            "min_depth",
            "max_depth",
            "system_last_updated",
            "system_first_seen",
            "location",
            "href_graph",
            "href_history",
            "href_threat",
            "tags",
            "sources",
            "sighting_sources",
            "scores",
            "metadata",
            "whitelist_sources",
            "hashes",
        }

        data = {k: v for k, v in data.items() if k in known_fields}

        for list_field in ("tags", "sources", "sighting_sources", "scores"):
            if list_field in data and data[list_field] is None:
                del data[list_field]

        if "content" in data:
            if "ip_content" in data["content"]:
                if "location" in data["content"]["ip_content"]:
                    location_data = data["content"]["ip_content"]["location"]
                    data["location"] = location_data
            if "file_content" in data["content"]:
                if "hashes" in data["content"]["file_content"]:
                    data["hashes"] = data["content"]["file_content"]["hashes"]

        return data


""" HELPER FUNCTIONS """

# --- Scoring & lookup ---


def is_valid_uuid(hex_string: str) -> bool:
    """Check if hex input is a valid UUID."""
    try:
        uuid.UUID(hex_string)
        return True
    except ValueError:
        return False


def get_enum_attribute(enum_class: type[T], attribute_name: str) -> T:
    """Look up a value by name in an enum (e.g. ThreatType, Visibility), raising DemistoException if not found."""
    try:
        return getattr(enum_class, attribute_name)
    except AttributeError:
        enum_name = enum_class.__name__.lower().replace("type", "").replace("_", " ")
        valid = ", ".join(e.name for e in enum_class)
        raise DemistoException(f"Invalid attribute value '{attribute_name}'. Expected one of: {valid}")


def get_atom_value_by_atom_type(content: dict, atom_type: AtomType | str) -> str | None:
    """Extract the atom_value from a threat content dict for the given atom type."""
    atom_type_value = atom_type.value if isinstance(atom_type, AtomType) else atom_type
    atom_type_mapping = {
        AtomType.IP.value: lambda c: c["ip_content"]["atom_value"],
        AtomType.FILE.value: lambda c: c["file_content"]["atom_value"],
        AtomType.DOMAIN.value: lambda c: c["domain_content"]["atom_value"],
        AtomType.EMAIL.value: lambda c: c["email_content"]["atom_value"],
        AtomType.URL.value: lambda c: c["url_content"]["atom_value"],
    }

    if atom_type_value not in atom_type_mapping:
        return None

    return atom_type_mapping[atom_type_value](content)


def verdict_to_dbotscore(risk: Verdict) -> int:
    """Map a verdict to its corresponding DBotScore."""
    match risk:
        case Verdict.NOT_FOUND:
            return Common.DBotScore.NONE
        case Verdict.UNSCORED:
            return Common.DBotScore.NONE
        case Verdict.BENIGN:
            return Common.DBotScore.GOOD
        case Verdict.SUSPICIOUS:
            return Common.DBotScore.SUSPICIOUS
        case Verdict.MALICIOUS:
            return Common.DBotScore.BAD
        case _:
            return Common.DBotScore.NONE


def get_indicator_type(atom_type: AtomType | str | None) -> str:
    """Map a Datalake atom type to its corresponding DBotScoreType."""
    value = atom_type.value if isinstance(atom_type, AtomType) else atom_type
    if value == AtomType.IP.value:
        return DBotScoreType.IP
    if value == AtomType.URL.value:
        return DBotScoreType.URL
    if value == AtomType.DOMAIN.value:
        return DBotScoreType.DOMAIN
    if value == AtomType.EMAIL.value:
        return DBotScoreType.EMAIL
    if value == AtomType.FILE.value:
        return DBotScoreType.FILE
    return DBotScoreType.CUSTOM


def decompress_one_element_list(nested_list: Any) -> Any:
    """Unwrap nested single-element lists down to the inner value."""
    if not isinstance(nested_list, list):
        return nested_list

    while isinstance(nested_list, list) and len(nested_list) == 1:
        nested_list = nested_list[0]

    return nested_list


# --- Indicator-object factories ---


def create_dbot_score_object(
    atom_value: str, atom_type: AtomType | str | None, verdict: Verdict, feed_reliability: str | None = None
) -> Common.DBotScore:
    """Build a Common.DBotScore for the given indicator and verdict."""
    dbot_score_value = verdict_to_dbotscore(verdict)
    indicator_type = get_indicator_type(atom_type)

    return Common.DBotScore(
        indicator=atom_value,
        indicator_type=indicator_type,
        integration_name="OCD Datalake",
        score=dbot_score_value,
        reliability=feed_reliability,
    )


def format_datalake_scores(scores: dict[str, int]) -> dict[str, str]:
    """Stringify scores and pad missing threat types with '-'."""
    normalized_scores = {k: str(v) for k, v in scores.items()}
    for t in (tt.value for tt in ThreatType):
        if t not in normalized_scores:
            normalized_scores[t] = "-"
    return normalized_scores


def create_atom(atom_value: str, atom_type: str) -> Atom:
    """Create a Datalake atom object based on type and value."""
    atom_class = SUPPORTED_SIGHTING_ATOM_TYPES.get(atom_type)
    if atom_class is None:
        raise DemistoException(f"Invalid atom_type given as param: '{atom_type}'")
    if atom_type == "FileAtom":
        hash_type = HASH_LENGTH_TO_HASH_TYPE.get(len(atom_value))
        if hash_type is None:
            raise DemistoException(f"Unsupported hash length ({len(atom_value)}) for file atom")
        return FileAtom(Hashes(**{hash_type: atom_value}))
    else:
        return atom_class(atom_value)


# --- File & batch I/O ---


def _generate_output_path() -> str:
    """Generate a unique output file path in the system temp directory."""
    return os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))


def stream_lines_of_file(filename: str) -> Iterator[str]:
    """Yield each line of a file with trailing newline stripped."""
    with open(filename, "r") as file:
        for line in file:
            yield line.rstrip("\n")


def write_http_stream_to_file(file_path: str, http_stream: requests.Response, skip_header: bool = True) -> int:
    """Write an HTTP streaming response to file line-by-line and return the number of lines written."""
    http_stream_iter = http_stream.iter_lines()

    if skip_header:
        next(http_stream_iter, None)

    count = 0
    with open(file_path, "w") as f:
        for chunk in http_stream_iter:
            if chunk:
                count += 1
                f.write(chunk.decode() + "\n")

    return count


def _convert_field(field: str) -> Any:
    """Convert a CSV field string to int, list, or leave as-is."""
    if field == "":
        return ""

    if field.isdigit():
        return int(field)

    if field.startswith("[") and field.endswith("]"):
        try:
            return json.loads(field)
        except json.JSONDecodeError:
            try:
                return ast.literal_eval(field)
            except (ValueError, SyntaxError):
                return field

    return field


def convert_csv_row(row: list[str]) -> list[Any]:
    """Convert each field of a CSV row to its appropriate Python type."""
    converted = []
    for f in row:
        converted.append(_convert_field(f))
    return converted


def get_batch_not_none(stream: Iterator[str]) -> list[list[Any]]:
    """Read up to BATCH_SIZE lines from the stream and parse them into typed CSV rows."""
    stream_slice = itertools.islice(stream, BATCH_SIZE)
    parsed_rows = csv.reader(list(stream_slice))
    processed_rows = list(map(convert_csv_row, parsed_rows))

    return processed_rows


def create_datalake_json_dict_from_list(value_list: list[Any]) -> dict[str, Any]:
    """Build a flat dict from a positional CSV row using DATALAKE_BULK_SEARCH_FIELDS as the schema."""
    mapped_object = {key: value for (key, value) in zip(DATALAKE_BULK_SEARCH_FIELDS, value_list)}

    if "threat_scores" in mapped_object and "threat_types" in mapped_object:
        mapped_object["threat_scores"] = {
            key: value for (key, value) in zip(mapped_object["threat_types"], mapped_object["threat_scores"])
        }

        del mapped_object["threat_types"]

    mappings = {
        ".location.country": "country",
        ".location.latitude": "latitude",
        ".location.longitude": "longitude",
        ".hashes.md5": "md5",
        ".hashes.sha1": "sha1",
        ".hashes.sha256": "sha256",
        ".hashes.sha512": "sha512",
        ".hashes.ssdeep": "ssdeep",
        ".filesize": "filesize",
        ".filetype": "filetype",
        ".filepath": "filepath",
        ".ip_version": "ip_version",
    }

    for key in mappings:
        if key in mapped_object:
            mapped_object[mappings[key]] = mapped_object[key]
            del mapped_object[key]

    return mapped_object


def get_indicator(client: DatalakeClient, datalake_result_item: list[Any]) -> dict[str, Any] | None:
    """Build an XSOAR indicator dict from a Datalake bulk-search CSV row, or None if the atom type is unsupported."""
    response = create_datalake_json_dict_from_list(datalake_result_item)

    atom_type = response.get("atom_type")
    indicator_type = ATOM_TYPE_TO_FEED_INDICATORS_TYPE.get(atom_type)
    if indicator_type is None:
        return None

    threat_scores = response.get("threat_scores")
    formatted_threat_scores = format_datalake_scores(threat_scores or {})
    max_risk = max(threat_scores.values()) if threat_scores else None

    indicator = {
        "value": response.get("atom_value"),
        "type": indicator_type,
        "source": "OCD Datalake",
        "score": verdict_to_dbotscore(client.get_verdict_from_max_score(max_risk)),
        "rawJSON": {
            "value": response.get("atom_value"),
            "type": indicator_type,
            "atom_type": atom_type,
            "threat_hashkey": response.get("threat_hashkey"),
            "threat_scores": formatted_threat_scores,
            "sources": response.get("sources") or [],
            "tags": response.get("tags") or [],
            "threat_entities": response.get("threat_entities") or [],
            "firstseen": response.get("first_seen"),
            "lastupdated": response.get("last_updated"),
        },
        "fields": {
            "tags": [],
            "datalaketags": list(response.get("tags") or []),
            "firstseenbysource": response.get("first_seen"),
            "lastseenbysource": response.get("last_updated"),
            "datalakescores": [formatted_threat_scores],
            "datalakehashkey": response.get("threat_hashkey"),
            "datalakesources": response.get("sources") or [],
            "datalakethreatentities": response.get("threat_entities") or [],
        },
    }

    if client.add_tags:
        indicator["fields"]["tags"].extend(response.get("tags") or [])

    if client.feed_tags:
        indicator["fields"]["tags"].extend(client.feed_tags)

    if client.tlp_color:
        indicator["fields"]["trafficlightprotocol"] = client.tlp_color

    if atom_type == "ip":
        if response.get("latitude") and response.get("longitude"):
            indicator["fields"]["geolocation"] = f"{response['latitude']}:{response['longitude']}"
        if response.get("country"):
            indicator["fields"]["geocountry"] = response["country"]
    elif atom_type == "file":
        for attr, label in DATALAKE_FILE_FIELDS_TO_FILE_FIELDS:
            value = response.get(attr)
            if value:
                indicator["fields"][label] = decompress_one_element_list(value)
        if response.get("filesize"):
            indicator["fields"]["Size"] = response["filesize"]

    return indicator


def create_indicators_from_batch(client: DatalakeClient, batch: list[list[Any]], tag: str) -> list[dict[str, Any]]:
    """Build XSOAR indicator dicts from a batch of parsed CSV rows, skipping invalid items."""
    indicators = []
    unsupported_count = 0

    for i, item in enumerate(batch):
        if not item:
            continue

        try:
            indicator = get_indicator(client, item)
            if indicator is None:
                unsupported_count += 1
                continue
            if tag:
                indicator["fields"]["tags"].append(tag)
            indicators.append(indicator)
        except Exception as e:
            demisto.debug(f"Error creating indicator from item {i}: {e}")

    if unsupported_count > 0:
        demisto.debug("Some indicators were skipped because their were of an unsupported atom type.")

    demisto.info(f"Created {len(indicators)} valid indicators from batch of {len(batch)} items")
    return indicators


def _process_batches_from_source(
    client: DatalakeClient,
    source: Iterator[str],
    tag: str,
    indicator_creator_func: Callable[[DatalakeClient, list[list[Any]], str], list[dict[str, Any]]],
) -> int:
    """Read the source in batches, build indicators and push them to XSOAR, returning the total uploaded."""
    total_count = 0
    batch_number = 0

    try:
        curr_batch = get_batch_not_none(source)

        while curr_batch:
            indicators = indicator_creator_func(client, curr_batch, tag)

            if not indicators:
                break

            demisto.createIndicators(indicators)
            batch_number += 1
            total_count += len(indicators)

            demisto.info(f"Uploaded batch no. {batch_number}, containing {len(indicators)} indicators.")

            curr_batch = get_batch_not_none(source)

    finally:
        source.close()

    return total_count


# --- Fetch cycle & bulk search ---


def check(client: DatalakeClient, atom_type: AtomType, atom_value: list[str]) -> list[CommandResults]:
    """Look up one or more indicators by their value."""
    bulk_items: list[ReputationResult] = client.check(atom_type, atom_value)
    commands_result = []

    for bulk_item in bulk_items:
        if not bulk_item.threat_details:
            result = bulk_item.create_not_found_result(client, atom_type)
        else:
            result = bulk_item.create_threat_found_result(client)

        commands_result.append(result)

    return commands_result


def check_hashkey(client: DatalakeClient, hashkeys: list[str]) -> list[CommandResults]:
    """Look up one or more indicators by their hashkey."""
    bulk_items: list[ReputationResult] = client.check_hashkey(hashkeys)
    commands_result = []

    for bulk_item in bulk_items:
        if not bulk_item.threat_details:
            result = bulk_item.create_not_found_result(client, atom_type=None)
        else:
            result = bulk_item.create_threat_found_result(client)
        commands_result.append(result)

    return commands_result


""" COMMAND FUNCTIONS """


def test_module_command(client: DatalakeClient) -> str:
    """SPECIAL COMMAND !test-module - Test API connectivity and authentication, returning 'ok' on success or a diagnostic message."""
    message: str = ""
    try:
        client.MyAccount.me()
        params = FeedParameters.from_args(demisto.params())
        params.get_query_hash_dict()
        message = "ok"
    except ConnectionError as e:
        message = f"Unable to connect to Datalake: {e}"
    except ValueError as e:
        message = f"Authentication error: {e}"
    except DemistoException as e:
        message = str(e)
    except Exception as e:
        message = f"Unexpected error: {e}"
    return message


def submit_sightings_command(client: DatalakeClient, args: dict[str, Any]) -> CommandResults:
    """COMMAND !datalake-submit-sightings - Submit a sighting batch to Datalake from raw command args."""
    sighting_args = SubmitSightingsArgs.from_args(args)
    res = client.Sightings.submit_sighting(**sighting_args.to_dict())
    readable_output = tableToMarkdown("Sighting submitted to Datalake", res)
    return CommandResults(
        outputs_prefix=SIGHTING_OUTPUTS_PREFIX,
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=res,
        raw_response=res,
    )


@polling_function(
    name="datalake-import-indicators",
    interval=POLLING_INTERVAL_SECONDS,
    poll_message="Polling for bulk search result, then uploading indicators",
    timeout=TIMEOUT_POLLING_FUNCTIONS_SECONDS,
)
def datalake_import_indicators_command(args: dict[str, Any], client: DatalakeClient) -> PollResult:
    """COMMAND !datalake-import-indicators - Poll for bulk search results and import indicators when ready."""
    args["output_file_type"] = "CSV"
    import_args: ImportIndicatorsArgs = ImportIndicatorsArgs.from_args(client, args)

    task = (
        client.BulkSearch.get_task(import_args.task_id)
        if import_args.task_id
        else client.create_bulk_task(import_args.query_body)
    )
    import_args.task_id = task.uuid

    with client.download_bulk_task(task, "CSV") as bulk_search_file:
        if bulk_search_file is None:
            return PollResult(
                continue_to_poll=True,
                response={"message": f"Response not ready yet, task uuid is {task.uuid}"},
                args_for_next_run=import_args.__dict__.copy(),
            )
        count = _process_batches_from_source(
            client, stream_lines_of_file(bulk_search_file), import_args.tag, create_indicators_from_batch
        )
        return PollResult(
            continue_to_poll=False,
            response=f"Indicators imported successfully ({count} indicators)",
            args_for_next_run=import_args.__dict__.copy(),
        )


@polling_function(
    name="datalake-bulk-search",
    interval=POLLING_INTERVAL_SECONDS,
    poll_message="Polling for bulk search result",
    timeout=TIMEOUT_POLLING_FUNCTIONS_SECONDS,
)
def datalake_bulk_search_command(args: dict[str, Any], client: DatalakeClient) -> PollResult:
    """COMMAND !datalake-bulk-search - Poll a Datalake bulk-search task and return its JSON dict or assembled CSV string when ready."""
    import_args: ImportIndicatorsArgs = ImportIndicatorsArgs.from_args(client, args)
    output_type = import_args.output_file_type

    task = (
        client.BulkSearch.get_task(import_args.task_id)
        if import_args.task_id
        else client.create_bulk_task(import_args.query_body)
    )
    import_args.task_id = task.uuid

    with client.download_bulk_task(task, output_type) as bulk_search_file:
        if bulk_search_file is None:
            return PollResult(
                continue_to_poll=True,
                response={"message": f"Response not ready yet, task uuid is {task.uuid}"},
                args_for_next_run=import_args.__dict__.copy(),
            )
        with open(bulk_search_file) as f:
            result = json.load(f) if output_type == "JSON" else f.read()
        return PollResult(
            continue_to_poll=False,
            response=result,
            args_for_next_run=import_args.__dict__.copy(),
        )


def fetch_indicators_command(client: DatalakeClient) -> None:
    """SPECIAL COMMAND !fetch-indicators - Run a single fetch cycle, importing indicators into the platform."""
    params = FeedParameters.from_args(demisto.params())
    params.validate()
    query_hash_dict = params.get_query_hash_dict()
    lookback_fetch_interval = params.get_lookback_seconds()

    start_time = datetime.now()
    total_indicator_count = 0
    errors: list[str] = []

    # Submit all bulk search tasks upfront so they queue on the platform simultaneously
    pending: dict[Any, str] = {}
    for tag, query_hash in query_hash_dict.items():
        demisto.debug(f"Submitting bulk search task for tag '{tag}'")
        query_body = client.get_qbody_from_qhash(query_hash)
        task = client.create_bulk_task(query_body, lookback_fetch_interval)
        pending[task] = tag

    deadline = datetime.now().timestamp() + BULK_SEARCH_TIMEOUT_SECONDS
    while pending:
        for task, tag in list(pending.items()):
            task.update()
            if task.state == BulkSearchTaskState.DONE:
                del pending[task]
                with client.download_bulk_task(task, "CSV") as bulk_search_file:
                    total_indicator_count += _process_batches_from_source(
                        client, stream_lines_of_file(bulk_search_file), tag, create_indicators_from_batch
                    )
            elif task.state in (
                BulkSearchTaskState.CANCELLED,
                BulkSearchTaskState.FAILED_ERROR,
                BulkSearchTaskState.FAILED_TIMEOUT,
                BulkSearchTaskState.FAILED_QUOTA_EXCEEDED,
                BulkSearchTaskState.FAILED_TOO_MANY_RESULTS,
            ):
                del pending[task]
                errors.append(f"Tag '{tag}': bulk search task {task.uuid} ended with state {task.state.value}")

        if pending:
            if datetime.now().timestamp() > deadline:
                for task in pending:
                    task.cancel()
                timed_out = [f"'{pending[t]}'" for t in pending]
                errors.append(f"Timed out waiting for bulk search tasks: {', '.join(timed_out)}")
                break
            time.sleep(BULK_SEARCH_INTERVAL_SECONDS)

    if errors:
        raise DemistoException("One or more bulk searches failed:\n" + "\n".join(errors))

    execution_time = datetime.now() - start_time
    demisto.info(f"Total time of indicators upload {execution_time}, number of indicators {total_indicator_count}")
    demisto.info("Fetch indicators cycle completed successfully")


def _reputation_command(client: DatalakeClient, args: dict[str, Any], command_name: str) -> list[CommandResults]:
    """COMMAND - Parse the command's comma/semicolon-separated values and dispatch to check or check_hashkey."""
    arg = args.get(command_name, "")
    if command_name == "datalake-lookup-hashkey":
        arg = args.get("hashkey", "")
    normalized = arg.replace(";", ",")
    values = []
    for value in normalized.split(","):
        value = value.strip()
        if value:
            values.append(value)

    if command_name == "datalake-lookup-hashkey" or command_name == "hashkey":
        if command_name == "hashkey":
            return_warning('The command "hashkey" is deprecated. Use "datalake-lookup-hashkey" instead.', exit=False)
        return check_hashkey(client, values)
    return check(client, AtomType(command_name), values)


""" MAIN FUNCTION """


def main() -> None:
    """Main function: initialize the Datalake client and dispatch the invoked command."""
    params = demisto.params()
    os.environ["OCD_DTL_USER_AGENT_INTEGRATION"] = f"datalake2paloaltocortex/{get_pack_version()}"
    client = DatalakeClient(
        longterm_token=params.get("longtermToken"),
        env=params.get("datalakeEnv"),
        suspicious_threshold=int(params.get("thresholdSuspicious", LOW_THRESHOLD)),
        malicious_threshold=int(params.get("thresholdMalicious", HIGH_THRESHOLD)),
        proxies=handle_proxy(),
        verify=not params.get("insecure", False),
        tlp_color=params.get("tlp_color"),
        feed_tags=argToList(params.get("feedTags")),
        add_tags=argToBoolean(params.get("addTags", True)),
        feed_reliability=params.get("feedReliability"),
    )

    command_name = demisto.command()
    demisto.debug(f"Command being called is {command_name}")

    try:
        if command_name == "test-module":
            return_results(test_module_command(client))

        elif command_name == "datalake-submit-sightings" or command_name == "submit_sightings":
            if command_name == "submit_sightings":
                return_warning(
                    'The command "submit_sightings" is deprecated. Use "datalake-submit-sightings" instead.', exit=False
                )
            if not client.has_permission("submit_sightings"):
                raise DemistoException("Your account does not have permission to submit sightings.")
            return_results(submit_sightings_command(client, demisto.args()))

        elif command_name == "datalake-bulk-search" or command_name == "bulk_search":
            if command_name == "bulk_search":
                return_warning('The command "bulk_search" is deprecated. Use "datalake-bulk-search" instead.', exit=False)
            if not client.has_permission("bulk_search"):
                raise DemistoException("Your account does not have permission to create bulk searches.")
            return_results(datalake_bulk_search_command(demisto.args(), client))

        elif command_name == "fetch-indicators":
            if not client.has_permission("bulk_search"):
                raise DemistoException("Your account does not have permission to create bulk searches.")
            fetch_indicators_command(client)

        elif command_name == "datalake-import-indicators" or command_name == "import-indicators":
            if command_name == "import-indicators":
                return_warning(
                    'The command "import-indicators" is deprecated. Use "datalake-import-indicators" instead.', exit=False
                )
            if not client.has_permission("bulk_search"):
                raise DemistoException("Your account does not have permission to create bulk searches.")
            return_results(datalake_import_indicators_command(demisto.args(), client))

        elif command_name in SUPPORTED_REPUTATION_COMMANDS:
            return_results(_reputation_command(client, demisto.args(), command_name))

        else:
            raise NotImplementedError(f"Command '{command_name}' is not implemented.")

    except Exception as e:
        # Keep historical behavior for IP validation errors (422): return a readable message.
        if command_name == "ip" and str(e).startswith("422"):
            return_results(f"Failed to execute '{command_name}' command.\nError:\n{str(e)}")
        else:
            error_message = str(e)
            if not isinstance(e, DemistoException):
                traceback_error = traceback.format_exc()
                demisto.error(traceback_error)
                error_message = f"Failed to execute {command_name} command.\nError: {str(e)}"
            return_error(error_message)


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
