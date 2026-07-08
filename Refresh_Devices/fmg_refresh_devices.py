#!/usr/bin/env python3
"""
FortiManager Device Refresh Tool

The tool reads the FortiManager address, API key, TLS behavior, and task
monitoring settings from config.ini.

Workflow:
1. Read FortiManager settings from config.ini.
2. Retrieve and select an ADOM.
3. Retrieve FortiGate devices from the selected ADOM.
4. Select one, multiple, or all devices.
5. Submit a nonblocking refresh task.
6. Monitor the task until completion.

Authentication:
    Authorization: Bearer <API_KEY>

Dependency:
    pip install requests
"""

from __future__ import annotations

import argparse
import configparser
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

import requests
from requests import Response, Session
from requests.exceptions import RequestException


# Only show ADOMs that can contain supported FortiGate-family devices.
ALLOWED_ADOM_PRODUCTS = frozenset(
    {
        "fos",
        "foc",
        "ffw",
        "fwc",
        "fpx",
        "fabric",
    }
)


class FMGError(RuntimeError):
    """Raised when configuration, HTTP, or FortiManager returns an error."""


@dataclass(frozen=True)
class AppConfig:
    url: str
    api_key: str
    verify_ssl: bool
    timeout: float
    poll_interval: float
    max_polls: int


@dataclass
class TaskSummary:
    task_id: int | str
    state: str
    progress: int
    completed: int
    running: int
    failed: int
    lines: list[dict[str, Any]]
    raw_task: dict[str, Any]


class Console:
    """Small ANSI-aware console helper with no external UI dependency."""

    def __init__(self) -> None:
        self.use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    def _wrap(self, code: str, text: str) -> str:
        if not self.use_color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def title(self, text: str) -> None:
        print(self._wrap("1;36", text))

    def info(self, text: str) -> None:
        print(f"{self._wrap('36', '[INFO]')} {text}")

    def success(self, text: str) -> None:
        print(f"{self._wrap('32', '[OK]')}   {text}")

    def warning(self, text: str) -> None:
        print(f"{self._wrap('33', '[WARN]')} {text}")

    def error(self, text: str) -> None:
        print(f"{self._wrap('31', '[ERROR]')} {text}", file=sys.stderr)

    def progress(self, text: str) -> None:
        if sys.stdout.isatty():
            print(f"\r\033[2K{text}", end="", flush=True)
        else:
            print(text)

    def finish_progress(self) -> None:
        if sys.stdout.isatty():
            print()


console = Console()


def normalize_jsonrpc_url(host: str) -> str:
    value = host.strip().rstrip("/")

    if not value:
        raise FMGError("The 'host' setting cannot be empty.")

    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"

    if not value.endswith("/jsonrpc"):
        value = f"{value}/jsonrpc"

    return value


def load_config(path: Path) -> AppConfig:
    """Load and validate FortiManager settings from an INI file."""

    parser = configparser.ConfigParser(interpolation=None)

    try:
        loaded_files = parser.read(path, encoding="utf-8")
    except (configparser.Error, OSError) as exc:
        raise FMGError(f"Unable to read configuration file '{path}': {exc}") from exc

    if not loaded_files:
        raise FMGError(
            f"Configuration file was not found: {path}\n"
            "Copy config.ini.example to config.ini and update its values."
        )

    section_name = "fortimanager"

    if not parser.has_section(section_name):
        raise FMGError(
            f"Configuration file '{path}' must contain a "
            f"[{section_name}] section."
        )

    section = parser[section_name]
    host = section.get("host", "").strip()
    api_key = section.get("api_key", "").strip()

    placeholders = {
        "",
        "PASTE_API_KEY_HERE",
        "<PASTE_API_KEY_HERE>",
        "YOUR_API_KEY_HERE",
        "<YOUR_API_KEY_HERE>",
    }

    if api_key in placeholders:
        raise FMGError(
            f"The 'api_key' value in '{path}' has not been configured."
        )

    if any(character.isspace() for character in api_key):
        raise FMGError(
            "The 'api_key' value must contain only the API key, "
            "without spaces or line breaks."
        )

    try:
        verify_ssl = section.getboolean("verify_ssl", fallback=True)
    except ValueError as exc:
        raise FMGError(
            "'verify_ssl' must be true or false."
        ) from exc

    try:
        timeout = section.getfloat("timeout", fallback=30.0)
        poll_interval = section.getfloat("poll_interval", fallback=2.0)
        max_polls = section.getint("max_polls", fallback=150)
    except ValueError as exc:
        raise FMGError(
            "'timeout' and 'poll_interval' must be numbers, and "
            "'max_polls' must be an integer."
        ) from exc

    if timeout <= 0:
        raise FMGError("'timeout' must be greater than zero.")

    if poll_interval < 0:
        raise FMGError("'poll_interval' cannot be negative.")

    if max_polls <= 0:
        raise FMGError("'max_polls' must be greater than zero.")

    return AppConfig(
        url=normalize_jsonrpc_url(host),
        api_key=api_key,
        verify_ssl=verify_ssl,
        timeout=timeout,
        poll_interval=poll_interval,
        max_polls=max_polls,
    )


def safe_text(value: Any, default: str = "") -> str:
    if value is None:
        return default

    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)

    return str(value)


def clamp_percent(value: Any) -> int:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0

    return max(0, min(100, round(number)))


def truncate(value: Any, width: int) -> str:
    text = safe_text(value, "—").replace("\n", " ").strip() or "—"

    if len(text) <= width:
        return text

    if width <= 1:
        return text[:width]

    return text[: width - 1] + "…"


def print_table(
    headers: list[str],
    rows: Iterable[Iterable[Any]],
    maximum_widths: list[int] | None = None,
) -> None:
    materialized = [[safe_text(cell, "—") for cell in row] for row in rows]

    if not materialized:
        print("(No entries)")
        return

    column_count = len(headers)

    if any(len(row) != column_count for row in materialized):
        raise ValueError("Every table row must have the same number of columns.")

    widths = [len(header) for header in headers]

    for row in materialized:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    if maximum_widths:
        widths = [
            min(width, maximum_widths[index])
            for index, width in enumerate(widths)
        ]

    def format_row(row: Iterable[Any]) -> str:
        cells = list(row)
        return " | ".join(
            truncate(cells[index], widths[index]).ljust(widths[index])
            for index in range(column_count)
        )

    print(format_row(headers))
    print("-+-".join("-" * width for width in widths))

    for row in materialized:
        print(format_row(row))


class FortiManagerClient:
    def __init__(self, config: AppConfig) -> None:
        self.url = config.url
        self.verify_ssl = config.verify_ssl
        self.timeout = config.timeout
        self.http: Session = requests.Session()
        self.http.headers.update(
            {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {config.api_key}",
            }
        )
        self._request_id = 0

        if not self.verify_ssl:
            try:
                requests.packages.urllib3.disable_warnings(  # type: ignore[attr-defined]
                    requests.packages.urllib3.exceptions.InsecureRequestWarning  # type: ignore[attr-defined]
                )
            except AttributeError:
                pass

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response: Response = self.http.post(
                self.url,
                json=payload,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.exceptions.SSLError as exc:
            raise FMGError(
                "TLS certificate verification failed. "
                "For a FortiManager using a self-signed certificate, "
                "set 'verify_ssl = false' in config.ini. "
                f"Original error: {exc}"
            ) from exc
        except RequestException as exc:
            raise FMGError(f"HTTP request failed: {exc}") from exc

        try:
            body = response.json()
        except ValueError as exc:
            preview = response.text[:500]
            raise FMGError(
                f"FortiManager returned invalid JSON. Response: {preview}"
            ) from exc

        if not isinstance(body, dict):
            raise FMGError("FortiManager returned an unexpected JSON structure.")

        return body

    @staticmethod
    def _extract_result(body: dict[str, Any]) -> dict[str, Any]:
        results = body.get("result")

        if not isinstance(results, list) or not results:
            raise FMGError(
                "FortiManager response did not contain a result entry."
            )

        result = results[0]

        if not isinstance(result, dict):
            raise FMGError("FortiManager returned an invalid result entry.")

        status = result.get("status") or {}
        code = status.get("code")
        message = status.get("message", "Unknown FortiManager error")

        try:
            numeric_code = int(code)
        except (TypeError, ValueError):
            numeric_code = None

        if numeric_code != 0:
            raise FMGError(
                f"FortiManager API error {code}: {message}"
            )

        return result

    def call(
        self,
        method: str,
        url: str,
        *,
        data: dict[str, Any] | None = None,
        fields: list[str] | None = None,
    ) -> dict[str, Any]:
        parameter: dict[str, Any] = {"url": url}

        if data is not None:
            parameter["data"] = data

        if fields is not None:
            parameter["fields"] = fields

        payload: dict[str, Any] = {
            "id": self._next_id(),
            "method": method,
            "params": [parameter],
            "verbose": 1,
        }

        body = self._post(payload)
        return self._extract_result(body)

    def close(self) -> None:
        self.http.close()

    def get_adoms(self) -> list[dict[str, Any]]:
        """
        Retrieve ADOMs and keep only FortiGate-family ADOMs.

        The rootp ADOM is excluded. An ADOM is included only when its
        restricted_prds value is one of the supported product codes:
        fos, foc, ffw, fwc, fpx, or fabric.
        """

        result = self.call(
            "get",
            "/dvmdb/adom",
            fields=["name", "restricted_prds"],
        )
        data = result.get("data", [])

        if isinstance(data, dict):
            data = [data]

        if not isinstance(data, list):
            raise FMGError("FortiManager returned an invalid ADOM list.")

        filtered_adoms: list[dict[str, Any]] = []

        for item in data:
            if not isinstance(item, dict):
                continue

            name = safe_text(item.get("name")).strip()

            if not name or name.lower() == "rootp":
                continue

            product_code = safe_text(
                item.get("restricted_prds")
            ).strip().lower()

            if product_code not in ALLOWED_ADOM_PRODUCTS:
                continue

            filtered_adoms.append(item)

        return sorted(
            filtered_adoms,
            key=lambda item: safe_text(item.get("name")).lower(),
        )

    def get_devices(self, adom: str) -> list[dict[str, Any]]:
        encoded_adom = quote(adom, safe="")
        result = self.call(
            "get",
            f"/dvmdb/adom/{encoded_adom}/device",
            fields=["name"],
        )
        data = result.get("data", [])

        if isinstance(data, dict):
            data = [data]

        if not isinstance(data, list):
            raise FMGError("FortiManager returned an invalid device list.")

        unique: dict[str, dict[str, Any]] = {}

        for item in data:
            if not isinstance(item, dict):
                continue

            name = safe_text(item.get("name")).strip()

            if name:
                unique.setdefault(name, item)

        return [
            unique[name]
            for name in sorted(unique, key=str.lower)
        ]

    def refresh_devices(
        self,
        adom: str,
        device_names: list[str],
    ) -> int | str:
        result = self.call(
            "exec",
            "/dvm/cmd/update/dev-list",
            data={
                "adom": adom,
                "flags": [
                    "create_task",
                    "nonblocking",
                ],
                "update-dev-member-list": [
                    {"name": name}
                    for name in device_names
                ],
            },
        )

        data = result.get("data") or {}

        if isinstance(data, list):
            data = data[0] if data else {}

        if not isinstance(data, dict):
            raise FMGError(
                "Refresh request succeeded but returned invalid task data."
            )

        task_id = data.get("taskid")

        if task_id is None:
            raise FMGError(
                "Refresh request succeeded but no task ID was returned."
            )

        return task_id

    def get_task(self, task_id: int | str) -> dict[str, Any]:
        result = self.call(
            "get",
            f"/task/task/{task_id}",
        )
        data = result.get("data") or {}

        if isinstance(data, list):
            data = data[0] if data else {}

        if not isinstance(data, dict):
            raise FMGError("FortiManager returned invalid task data.")

        return data


def choose_one(
    items: list[dict[str, Any]],
    *,
    title: str,
    label_key: str,
) -> dict[str, Any]:
    if not items:
        if title == "Available ADOMs":
            supported = ", ".join(sorted(ALLOWED_ADOM_PRODUCTS))
            raise FMGError(
                "No supported FortiGate-family ADOMs were returned. "
                f"Allowed restricted_prds values: {supported}."
            )

        raise FMGError(f"No {title.lower()} were returned.")

    print()
    console.title(title)

    rows = [
        (index, safe_text(item.get(label_key)))
        for index, item in enumerate(items, start=1)
    ]
    print_table(["#", label_key.capitalize()], rows, [6, 70])

    while True:
        raw = input(f"\nSelect {label_key} [1-{len(items)}]: ").strip()

        try:
            selected = int(raw)
        except ValueError:
            console.warning("Enter a valid number.")
            continue

        if 1 <= selected <= len(items):
            return items[selected - 1]

        console.warning(
            f"Selection must be between 1 and {len(items)}."
        )


def parse_device_selection(raw: str, item_count: int) -> list[int]:
    selection = raw.strip().lower()

    if selection in {"all", "a", "*"}:
        return list(range(item_count))

    if not selection:
        raise ValueError("Selection cannot be empty.")

    selected: list[int] = []

    for token in selection.split(","):
        token = token.strip()

        if not token:
            raise ValueError("Selection contains an empty value.")

        if "-" in token:
            parts = token.split("-", maxsplit=1)

            if len(parts) != 2:
                raise ValueError(f"Invalid range: {token}")

            try:
                start = int(parts[0])
                end = int(parts[1])
            except ValueError as exc:
                raise ValueError(f"Invalid range: {token}") from exc

            if start > end:
                raise ValueError(
                    f"Range start must not exceed range end: {token}"
                )

            numbers = range(start, end + 1)
        else:
            try:
                numbers = [int(token)]
            except ValueError as exc:
                raise ValueError(
                    f"Invalid device number: {token}"
                ) from exc

        for number in numbers:
            if not 1 <= number <= item_count:
                raise ValueError(
                    f"Device number {number} is outside 1-{item_count}."
                )

            zero_based = number - 1

            if zero_based not in selected:
                selected.append(zero_based)

    return selected


def choose_devices(
    devices: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not devices:
        raise FMGError("No FortiGate devices were found in the ADOM.")

    print()
    console.title("FortiGate Devices")

    rows = [
        (index, safe_text(device.get("name")))
        for index, device in enumerate(devices, start=1)
    ]
    print_table(["#", "Device"], rows, [6, 80])

    print(
        "\nSelection examples:"
        "\n  1           One device"
        "\n  1,3,7       Multiple devices"
        "\n  2-5         A range"
        "\n  1,4-6,9     Combined values and ranges"
        "\n  all         Every listed device"
    )

    while True:
        raw = input("\nSelect device(s) to refresh: ")

        try:
            indexes = parse_device_selection(raw, len(devices))
        except ValueError as exc:
            console.warning(str(exc))
            continue

        return [devices[index] for index in indexes]


def normalize_task_state(
    state: Any,
    percent: int,
    error_code: int,
) -> str:
    if error_code != 0:
        return "failed"

    normalized = safe_text(state).strip().lower()

    if normalized in {
        "done",
        "complete",
        "completed",
        "success",
        "successful",
        "finished",
    }:
        return "done"

    if normalized in {
        "error",
        "failed",
        "failure",
        "aborted",
        "cancelled",
        "canceled",
        "timeout",
    }:
        return "failed"

    if normalized in {
        "running",
        "pending",
        "queued",
        "started",
        "processing",
        "in progress",
        "in_progress",
    }:
        return "running"

    if not normalized and percent >= 100:
        return "done"

    return normalized or "running"


def summarize_task(
    task_id: int | str,
    task: dict[str, Any],
) -> TaskSummary:
    raw_lines = task.get("line") or []

    if isinstance(raw_lines, dict):
        raw_lines = [raw_lines]

    if not isinstance(raw_lines, list):
        raw_lines = []

    lines: list[dict[str, Any]] = []

    for raw_line in raw_lines:
        if not isinstance(raw_line, dict):
            continue

        try:
            error_code = int(
                raw_line.get("err", raw_line.get("error", 0)) or 0
            )
        except (TypeError, ValueError):
            error_code = -1

        percent = clamp_percent(
            raw_line.get("percent", raw_line.get("progress", 0))
        )
        state = normalize_task_state(
            raw_line.get("state"),
            percent,
            error_code,
        )

        lines.append(
            {
                "name": (
                    raw_line.get("name")
                    or raw_line.get("device")
                    or raw_line.get("devname")
                    or "Unknown device"
                ),
                "vdom": (
                    raw_line.get("vdom")
                    or raw_line.get("vdom_name")
                    or "—"
                ),
                "state": state,
                "percent": percent,
                "err": error_code,
                "detail": (
                    raw_line.get("detail")
                    or raw_line.get("message")
                    or raw_line.get("description")
                    or ""
                ),
            }
        )

    completed = sum(
        1
        for line in lines
        if line["state"] == "done" and line["err"] == 0
    )
    failed = sum(
        1
        for line in lines
        if line["state"] == "failed" or line["err"] != 0
    )
    running = max(len(lines) - completed - failed, 0)

    if lines:
        progress = round(
            sum(line["percent"] for line in lines) / len(lines)
        )
    else:
        progress = clamp_percent(task.get("percent", 0))

    raw_state = safe_text(
        task.get("state", task.get("status", ""))
    )
    state = normalize_task_state(raw_state, progress, 0)

    if state not in {"done", "failed"} and lines:
        if completed + failed == len(lines):
            state = "failed" if failed else "done"

    return TaskSummary(
        task_id=task.get("id", task_id),
        state=state,
        progress=progress,
        completed=completed,
        running=running,
        failed=failed,
        lines=lines,
        raw_task=task,
    )


def monitor_task(
    client: FortiManagerClient,
    task_id: int | str,
    *,
    poll_interval: float,
    max_polls: int,
) -> TaskSummary:
    terminal_states = {"done", "failed"}
    previous_line = ""

    for poll_number in range(1, max_polls + 1):
        task = client.get_task(task_id)
        summary = summarize_task(task_id, task)

        status_line = (
            f"Task {summary.task_id} | "
            f"state={summary.state} | "
            f"progress={summary.progress}% | "
            f"completed={summary.completed} | "
            f"running={summary.running} | "
            f"failed={summary.failed} | "
            f"poll={poll_number}/{max_polls}"
        )

        if sys.stdout.isatty() or status_line != previous_line:
            console.progress(status_line)
            previous_line = status_line

        if summary.state in terminal_states:
            console.finish_progress()
            return summary

        if poll_number < max_polls:
            time.sleep(poll_interval)

    console.finish_progress()
    raise FMGError(
        f"Task {task_id} did not finish after {max_polls} polling attempts."
    )


def display_task_result(summary: TaskSummary) -> None:
    print()
    console.title("Refresh Task Result")
    print(f"Task ID    : {summary.task_id}")
    print(f"State      : {summary.state}")
    print(f"Progress   : {summary.progress}%")
    print(f"Completed  : {summary.completed}")
    print(f"Failed     : {summary.failed}")
    print(f"In progress: {summary.running}")

    if not summary.lines:
        console.warning(
            "FortiManager did not return per-device task lines."
        )
        return

    print()
    rows = [
        (
            line["name"],
            line["vdom"],
            line["state"],
            f"{line['percent']}%",
            line["err"] if line["err"] else "—",
            line["detail"] or "—",
        )
        for line in summary.lines
    ]

    print_table(
        [
            "Device",
            "VDOM",
            "Status",
            "Progress",
            "Error",
            "Details",
        ],
        rows,
        [35, 15, 12, 10, 8, 70],
    )


def confirm_refresh(
    adom: str,
    selected_devices: list[dict[str, Any]],
) -> bool:
    print()
    console.title("Selected Refresh Scope")
    print(f"ADOM         : {adom}")
    print(f"Device count : {len(selected_devices)}")

    for device in selected_devices:
        print(f"  - {safe_text(device.get('name'))}")

    answer = input("\nStart the refresh task? [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Select an ADOM and one, multiple, or all FortiGate devices, "
            "then refresh them through FortiManager."
        )
    )
    parser.add_argument(
        "--config",
        default=str(Path(__file__).resolve().with_name("config.ini")),
        help=(
            "Path to the INI configuration file. "
            "Default: config.ini beside this script."
        ),
    )
    parser.add_argument(
        "--adom",
        help=(
            "Use this ADOM directly instead of selecting from the "
            "retrieved ADOM list."
        ),
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    print()
    console.title("FortiManager Device Refresh Tool")
    print("=" * 37)

    config_path = Path(args.config).expanduser().resolve()

    try:
        config = load_config(config_path)
    except FMGError as exc:
        console.error(str(exc))
        return 2

    console.info(f"Using configuration: {config_path}")
    console.info(f"FortiManager endpoint: {config.url}")
    console.info(
        "TLS certificate verification: "
        + ("enabled" if config.verify_ssl else "disabled")
    )

    client = FortiManagerClient(config)
    exit_code = 1

    try:
        if args.adom:
            adom = args.adom
            console.info(f"Using ADOM: {adom}")
        else:
            console.info("Retrieving ADOMs.")
            adoms = client.get_adoms()
            selected_adom = choose_one(
                adoms,
                title="Available ADOMs",
                label_key="name",
            )
            adom = safe_text(selected_adom.get("name"))
            console.success(f"Selected ADOM: {adom}")

        console.info(f"Retrieving FortiGate devices from ADOM '{adom}'.")
        devices = client.get_devices(adom)
        console.success(f"Found {len(devices)} device(s).")

        selected_devices = choose_devices(devices)

        if not confirm_refresh(adom, selected_devices):
            console.warning("Refresh cancelled by the user.")
            return 0

        selected_names = [
            safe_text(device.get("name"))
            for device in selected_devices
        ]

        console.info(
            f"Submitting refresh for {len(selected_names)} device(s)."
        )
        task_id = client.refresh_devices(adom, selected_names)
        console.success(f"Refresh task created. Task ID: {task_id}")

        summary = monitor_task(
            client,
            task_id,
            poll_interval=config.poll_interval,
            max_polls=config.max_polls,
        )
        display_task_result(summary)

        if summary.state == "done" and summary.failed == 0:
            console.success("Device refresh completed successfully.")
            exit_code = 0
        else:
            console.error(
                "Device refresh completed with one or more failures."
            )
            exit_code = 1

    except KeyboardInterrupt:
        console.finish_progress()
        console.warning("Operation interrupted by the user.")
        exit_code = 130
    except FMGError as exc:
        console.finish_progress()
        console.error(str(exc))
        exit_code = 1
    finally:
        client.close()

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
