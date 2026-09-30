#!/usr/bin/env python3
"""OpenEMR CVE analysis and Metasploit cross-reference pipeline.

This module performs two related tasks:
1. Analyze OpenEMR CVEs by publication year and CVSS score.
2. Cross-reference OpenEMR CVEs with the official Metasploit module metadata.

The implementation is intentionally class-based so each responsibility can be
reused independently or executed together through ``OpenEMRAnalysisPipeline``.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd


LOGGER = logging.getLogger(__name__)

METASPLOIT_METADATA_URL = (
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/"
    "master/db/modules_metadata_base.json"
)

CVSS_SCORE_COLUMNS = (
    "CVSS 4.0 Score",
    "CVSS 3.1 Score",
    "CVSS 3.0 Score",
    "CVSS 2.0 Score",
)


@dataclass(frozen=True)
class PipelineConfig:
    """Configuration for the OpenEMR CVE analysis pipeline."""

    input_csv: Path
    output_dir: Path = Path("results")
    cve_column: str = "CVE"
    published_column: str = "Published"
    metadata_url: str = METASPLOIT_METADATA_URL
    request_timeout: int = 30

    @property
    def annual_summary_csv(self) -> Path:
        return self.output_dir / "openemr_cve_cvss_by_year.csv"

    @property
    def annual_plot_png(self) -> Path:
        return self.output_dir / "openemr_cve_cvss_by_year.png"

    @property
    def annual_plot_pdf(self) -> Path:
        return self.output_dir / "openemr_cve_cvss_by_year.pdf"

    @property
    def matched_modules_csv(self) -> Path:
        return self.output_dir / "openemr_cves_with_metasploit_modules.csv"

    @property
    def unmatched_cves_csv(self) -> Path:
        return self.output_dir / "openemr_cves_without_metasploit_modules.csv"


class OpenEMRCVEAnalyzer:
    """Load, validate, summarize, and visualize OpenEMR CVE data."""

    def __init__(self, config: PipelineConfig) -> None:
        self.config = config
        self.data: pd.DataFrame | None = None
        self.annual_summary: pd.DataFrame | None = None

    def load_data(self) -> pd.DataFrame:
        """Load the source CSV and validate columns needed for analysis."""
        LOGGER.info("Loading CVE dataset from %s", self.config.input_csv)
        data = pd.read_csv(self.config.input_csv)

        required_columns = {
            self.config.cve_column,
            self.config.published_column,
            *CVSS_SCORE_COLUMNS,
        }
        missing_columns = sorted(required_columns.difference(data.columns))
        if missing_columns:
            raise ValueError(
                "Input CSV is missing required column(s): "
                + ", ".join(missing_columns)
            )

        self.data = data
        return data

    def prepare_data(self) -> pd.DataFrame:
        """Normalize dates and select the newest available CVSS score per CVE."""
        if self.data is None:
            self.load_data()

        assert self.data is not None
        data = self.data.copy()

        data[self.config.published_column] = pd.to_datetime(
            data[self.config.published_column], errors="coerce"
        )
        data["Publication Year"] = data[self.config.published_column].dt.year

        for column in CVSS_SCORE_COLUMNS:
            data[column] = pd.to_numeric(data[column], errors="coerce")

        # Priority: CVSS 4.0 -> 3.1 -> 3.0 -> 2.0.
        data["Selected CVSS"] = data[list(CVSS_SCORE_COLUMNS)].bfill(axis=1).iloc[:, 0]

        self.data = data
        return data

    def build_annual_summary(self) -> pd.DataFrame:
        """Aggregate CVE counts and average selected CVSS scores by year."""
        if self.data is None or "Publication Year" not in self.data.columns:
            self.prepare_data()

        assert self.data is not None
        annual = (
            self.data.dropna(subset=["Publication Year"])
            .groupby("Publication Year")
            .agg(
                CVE_Count=(self.config.cve_column, "count"),
                Average_CVSS=("Selected CVSS", "mean"),
                CVSS_Scored_CVEs=("Selected CVSS", "count"),
            )
            .reset_index()
        )

        annual["Publication Year"] = annual["Publication Year"].astype(int)
        annual["Average_CVSS"] = annual["Average_CVSS"].round(2)
        self.annual_summary = annual
        return annual

    def save_annual_summary(self) -> Path:
        """Write the yearly CVE/CVSS summary to CSV."""
        if self.annual_summary is None:
            self.build_annual_summary()

        assert self.annual_summary is not None
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        self.annual_summary.to_csv(self.config.annual_summary_csv, index=False)
        LOGGER.info("Saved annual summary: %s", self.config.annual_summary_csv)
        return self.config.annual_summary_csv

    def create_plot(self, show: bool = False) -> tuple[Path, Path]:
        """Create and save the yearly CVE-count/CVSS visualization."""
        if self.annual_summary is None:
            self.build_annual_summary()

        assert self.annual_summary is not None
        if self.annual_summary.empty:
            raise ValueError("No valid publication years were found; plot cannot be created.")

        annual = self.annual_summary
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        figure, count_axis = plt.subplots(figsize=(11, 5.8))
        bars = count_axis.bar(
            annual["Publication Year"],
            annual["CVE_Count"],
            alpha=0.85,
        )

        count_axis.set_xlabel("Publication Year", fontsize=18)
        count_axis.set_ylabel("Number of OpenEMR CVEs", fontsize=18)
        count_axis.set_xticks(annual["Publication Year"])
        count_axis.tick_params(axis="x", rotation=45, labelsize=15)
        count_axis.tick_params(axis="y", labelsize=15)
        count_axis.grid(axis="y", alpha=0.25)

        cvss_axis = count_axis.twinx()
        cvss_axis.plot(
            annual["Publication Year"],
            annual["Average_CVSS"],
            marker="o",
            linewidth=2,
        )
        cvss_axis.set_ylabel("Average CVSS Score", fontsize=18)
        cvss_axis.set_ylim(0, 10)
        cvss_axis.tick_params(axis="y", labelsize=15)

        max_count = annual["CVE_Count"].max()
        label_offset = max(max_count * 0.012, 0.1)
        for bar, count in zip(bars, annual["CVE_Count"]):
            count_axis.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + label_offset,
                str(count),
                ha="center",
                va="bottom",
                fontsize=12,
            )

        for year, score in zip(annual["Publication Year"], annual["Average_CVSS"]):
            if pd.notna(score):
                cvss_axis.annotate(
                    f"{score:.2f}",
                    (year, score),
                    textcoords="offset points",
                    xytext=(0, 7),
                    ha="center",
                    fontsize=15,
                )

        figure.tight_layout()
        figure.savefig(self.config.annual_plot_png, dpi=300, bbox_inches="tight")
        figure.savefig(self.config.annual_plot_pdf, bbox_inches="tight")

        if show:
            plt.show()
        plt.close(figure)

        LOGGER.info("Saved plot: %s", self.config.annual_plot_png)
        LOGGER.info("Saved plot: %s", self.config.annual_plot_pdf)
        return self.config.annual_plot_png, self.config.annual_plot_pdf

    def get_cves(self) -> list[str]:
        """Return unique normalized CVE identifiers from the loaded dataset."""
        if self.data is None:
            self.load_data()

        assert self.data is not None
        cves = (
            self.data[self.config.cve_column]
            .dropna()
            .astype(str)
            .str.strip()
            .str.upper()
        )
        return list(dict.fromkeys(cve for cve in cves if cve))


class MetasploitMatcher:
    """Cross-reference CVE identifiers with official Metasploit metadata."""

    def __init__(self, config: PipelineConfig) -> None:
        self.config = config

    def fetch_metadata(self) -> dict[str, dict[str, Any]]:
        """Download and decode the official Metasploit module metadata."""
        LOGGER.info("Fetching Metasploit metadata")
        request = urllib.request.Request(
            self.config.metadata_url,
            headers={"User-Agent": "openemr-cve-analysis/1.0"},
        )

        try:
            with urllib.request.urlopen(
                request, timeout=self.config.request_timeout
            ) as response:
                payload = response.read()
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            raise RuntimeError(
                f"Could not retrieve Metasploit metadata: {reason}"
            ) from exc

        try:
            metadata = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Metasploit metadata response was not valid JSON.") from exc

        if not isinstance(metadata, dict):
            raise RuntimeError("Unexpected Metasploit metadata format.")

        return metadata

    @staticmethod
    def build_cve_index(
        metadata: dict[str, dict[str, Any]],
    ) -> dict[str, list[tuple[str, dict[str, Any]]]]:
        """Build an index from CVE identifier to matching Metasploit modules."""
        index: dict[str, list[tuple[str, dict[str, Any]]]] = {}

        for module_path, module_info in metadata.items():
            references = module_info.get("references", []) or []
            for reference in references:
                normalized_reference = str(reference).upper().strip()
                if normalized_reference.startswith("CVE-"):
                    index.setdefault(normalized_reference, []).append(
                        (module_path, module_info)
                    )

        return index

    def match_cves(
        self,
        cves: list[str],
        metadata: dict[str, dict[str, Any]] | None = None,
    ) -> tuple[list[dict[str, str]], list[str]]:
        """Return matched Metasploit module rows and CVEs with no match."""
        if metadata is None:
            metadata = self.fetch_metadata()

        cve_index = self.build_cve_index(metadata)
        matched_rows: list[dict[str, str]] = []
        unmatched_cves: list[str] = []

        for cve in cves:
            matches = cve_index.get(cve, [])
            if not matches:
                unmatched_cves.append(cve)
                continue

            for module_path, module_info in matches:
                matched_rows.append(
                    {
                        "CVE": cve,
                        "Module Path": module_path,
                        "Module Name": str(module_info.get("name", "Unknown")),
                        "Type": str(module_info.get("type", "unknown")),
                        "Rank": str(module_info.get("rank", "unknown")),
                    }
                )

        return matched_rows, unmatched_cves

    def save_results(
        self,
        matched_rows: list[dict[str, str]],
        unmatched_cves: list[str],
    ) -> tuple[Path, Path]:
        """Save matched and unmatched CVE results to separate CSV files."""
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        fieldnames = ["CVE", "Module Path", "Module Name", "Type", "Rank"]
        with self.config.matched_modules_csv.open(
            "w", newline="", encoding="utf-8"
        ) as file_handle:
            writer = csv.DictWriter(file_handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(matched_rows)

        with self.config.unmatched_cves_csv.open(
            "w", newline="", encoding="utf-8"
        ) as file_handle:
            writer = csv.writer(file_handle)
            writer.writerow(["CVE"])
            writer.writerows([[cve] for cve in unmatched_cves])

        LOGGER.info("Saved matched CVEs: %s", self.config.matched_modules_csv)
        LOGGER.info("Saved unmatched CVEs: %s", self.config.unmatched_cves_csv)
        return self.config.matched_modules_csv, self.config.unmatched_cves_csv


class OpenEMRAnalysisPipeline:
    """Coordinate CVE/CVSS analysis and optional Metasploit matching."""

    def __init__(self, config: PipelineConfig) -> None:
        self.config = config
        self.analyzer = OpenEMRCVEAnalyzer(config)
        self.matcher = MetasploitMatcher(config)

    def run(
        self,
        *,
        create_plot: bool = True,
        match_metasploit: bool = True,
        show_plot: bool = False,
    ) -> None:
        """Run the selected pipeline stages and print a concise summary."""
        self.analyzer.prepare_data()
        annual = self.analyzer.build_annual_summary()
        self.analyzer.save_annual_summary()

        if create_plot:
            self.analyzer.create_plot(show=show_plot)

        print("\nYearly OpenEMR CVE/CVSS summary:")
        print(annual.to_string(index=False))

        if not match_metasploit:
            return

        cves = self.analyzer.get_cves()
        metadata = self.matcher.fetch_metadata()
        matched_rows, unmatched_cves = self.matcher.match_cves(cves, metadata)
        self.matcher.save_results(matched_rows, unmatched_cves)

        matched_cves = {row["CVE"] for row in matched_rows}
        print("\nMetasploit cross-reference summary:")
        print(f"Total CVEs checked:               {len(cves)}")
        print(f"CVEs with >=1 Metasploit module: {len(matched_cves)}")
        print(f"CVEs with no Metasploit module:  {len(unmatched_cves)}")
        print(f"Total matching module entries:   {len(matched_rows)}")


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Analyze OpenEMR CVEs by year/CVSS and cross-reference them "
            "with Metasploit modules."
        )
    )
    parser.add_argument(
        "input_csv",
        type=Path,
        help="Path to the OpenEMR CVE CSV dataset.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results"),
        help="Directory for generated CSV and plot files (default: results).",
    )
    parser.add_argument(
        "--skip-plot",
        action="store_true",
        help="Skip PNG/PDF plot generation.",
    )
    parser.add_argument(
        "--skip-metasploit",
        action="store_true",
        help="Skip Metasploit metadata download and CVE matching.",
    )
    parser.add_argument(
        "--show-plot",
        action="store_true",
        help="Display the plot interactively after saving it.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed logging.",
    )
    return parser.parse_args()


def configure_logging(verbose: bool) -> None:
    """Configure console logging for command-line execution."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )


def main() -> int:
    """Command-line entry point."""
    args = parse_arguments()
    configure_logging(args.verbose)

    config = PipelineConfig(
        input_csv=args.input_csv,
        output_dir=args.output_dir,
    )

    try:
        pipeline = OpenEMRAnalysisPipeline(config)
        pipeline.run(
            create_plot=not args.skip_plot,
            match_metasploit=not args.skip_metasploit,
            show_plot=args.show_plot,
        )
    except (FileNotFoundError, ValueError, RuntimeError, pd.errors.ParserError) as exc:
        LOGGER.error("%s", exc)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
