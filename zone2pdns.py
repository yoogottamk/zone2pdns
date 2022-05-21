import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

import requests

from zoneparser import DNSRecordError, parse_zonefile

# host:port, no protocol
PDNS_API_HOST = os.getenv("PDNS_API_HOST", "localhost:8081")
# check GET /api/v1/servers to list all servers
PDNS_SERVER = os.getenv("PDNS_SERVER", "localhost")
PDNS_API_KEY = os.getenv("PDNS_API_KEY")


@dataclass
class PDNSComment:
    content: str
    account: str

    def to_dict(self):
        return {"content": self.content, "account": self.account}


@dataclass
class PDNSRecord:
    content: str
    disabled: bool

    def __eq__(self, other):
        return self.content == other.content

    def to_dict(self):
        return {"content": self.content, "disabled": self.disabled}


@dataclass
class PDNSResourceRecord:
    name: str
    type: str
    ttl: str
    changetype: str
    records: List[PDNSRecord]
    comments: List[PDNSComment]

    def __eq__(self, other):
        return self.name == other.name and self.type == other.type

    def to_dict(self):
        return {
            "name": self.name,
            "type": self.type,
            "ttl": self.ttl,
            "changetype": self.changetype,
            "records": [r.to_dict() for r in self.records],
            "comments": [c.to_dict() for c in self.comments],
        }

    def verify_and_prune_records(self):
        if len(self.records) <= 1:
            return
        sorted_records_idx = sorted(
            range(len(self.records)), key=lambda r: self.records[r].content
        )
        to_del = []
        for i in range(1, len(self.records)):
            if (
                self.records[sorted_records_idx[i]]
                == self.records[sorted_records_idx[i - 1]]
            ):
                # prefer deleting older record
                to_del_idx = sorted_records_idx[i - 1]
                # prefer deleting disabled record
                if self.records[sorted_records_idx[i]].disabled:
                    to_del_idx = sorted_records_idx[i]
                to_del.append(to_del_idx)

        self.records = [r for i, r in enumerate(self.records) if i not in set(to_del)]
        self.comments = [c for i, c in enumerate(self.comments) if i not in set(to_del)]


def load_zonefile(zonefile_path: str) -> Tuple[List[str], List[str]]:
    """
    Read zonefile and get list of commented and active records
    """
    lines = Path(zonefile_path).read_text().split("\n")

    active_lines = []
    commented_lines = []

    for l in lines:
        # need to add $ORIGIN in both
        if l.strip().startswith("$"):
            commented_lines.append(l)
            active_lines.append(l)
        # for disabled records
        elif l.strip().startswith(";"):
            commented_lines.append(l.split(";", 1)[1].strip())
        # normal records
        else:
            active_lines.append(l)

    return active_lines, commented_lines


def parse_records(zonefile_lines: List[str], zone: str, active=True):
    """
    Use zoneparser to parse lines
    """
    parsed_records = []

    for rec in parse_zonefile(zonefile_lines, zone):
        if type(rec) is DNSRecordError:
            print(rec, file=sys.stderr)
        else:
            parsed_records.append(
                PDNSResourceRecord(
                    name=rec.domain,
                    type=rec.type,
                    ttl=str(rec.ttl),
                    changetype="REPLACE",
                    records=[PDNSRecord(content=str(rec.value), disabled=not active)],
                    comments=[PDNSComment(content=rec.comment, account="admin")],
                )
            )

    return parsed_records


def merge_records(records: List[PDNSResourceRecord]):
    """
    Merge records of the same type

    For example,
    ```
        ...
        $ORIGIN example.com.
        @       NS      ns1
        @       NS      ns2
        ...
    ```
    will be merged into a single rrset containing 2 records and comments
    """
    sorted_rrs = sorted(records, key=lambda rr: f"{rr.name}:{rr.type}")
    merged_rrsets = [sorted_rrs[0]]

    for i in range(1, len(sorted_rrs)):
        # same record, merge "records" and "comments"
        if sorted_rrs[i] == merged_rrsets[-1]:
            merged_rrsets[-1].records += sorted_rrs[i].records
            merged_rrsets[-1].comments += sorted_rrs[i].comments
        else:
            # check for duplicates (either active or commented)
            merged_rrsets[-1].verify_and_prune_records()
            merged_rrsets.append(sorted_rrs[i])

    # what if it didn't enter the else block in the last iter?
    merged_rrsets[-1].verify_and_prune_records()

    return merged_rrsets


def build_pdns_rrsets(zonefile_path: str, zone: str) -> List[dict]:
    """
    zone file -> pdns json payload
    """
    active_lines, commented_lines = load_zonefile(zonefile_path)

    rrsets = parse_records(active_lines, zone) + parse_records(
        commented_lines, zone, active=False
    )
    merged_rrsets = merge_records(rrsets)

    payload = [rr.to_dict() for rr in merged_rrsets]
    return payload


if __name__ == "__main__":
    assert len(sys.argv) == 3, f"Usage: {sys.argv[0]} ZONE path/to/zonefile"
    zone, zonefile_path = sys.argv[1:3]

    payload = build_pdns_rrsets(zonefile_path, zone)

    print(
        f"Will add {len(payload)} records. Proceed? [y/p(rint)/N] ",
        end="",
        file=sys.stderr,
    )
    prompt_resp = input().strip().lower()
    if prompt_resp == "y":
        r = requests.patch(
            f"http://{PDNS_API_HOST}/api/v1/servers/{PDNS_SERVER}/zones/{zone}.",
            json={"rrsets": payload},
            headers={"X-Api-Key": PDNS_API_KEY},
        )
        if not r.ok:
            print(r.reason, r.text, sep="\n", end="\n---\n")
    elif prompt_resp == "p":
        print(json.dumps(payload, indent=4))
    else:
        print("Quitting")
