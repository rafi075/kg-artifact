from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

FIELD_ORDER = [
    "Reason",
    "AttackerAction",
    "Consequence",
    "Trigger",
    "SystemState",
    "Source",
    "VulnerabilityType",
]

FIELD_LABELS = {
    "Reason": "Reason",
    "AttackerAction": "Attacker\nAction",
    "Consequence": "Consequence",
    "Trigger": "Trigger",
    "SystemState": "System\nState",
    "Source": "Source",
    "VulnerabilityType": "Vuln.\nType",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create KG semantic evaluation figures.")
    parser.add_argument("--input_dir", default="kg_statistics")
    parser.add_argument("--output_dir", default="kg_eval_figures")
    parser.add_argument("--hist_output_name", default="semantic_score_histogram_compact")
    parser.add_argument("--reuse_output_name", default="semantic_reuse_boxplot")
    parser.add_argument("--component_count_output_name", default="component_count_vs_threshold")
    parser.add_argument("--component_size_output_name", default="avg_component_size_vs_threshold")
    return parser.parse_args()


def ordered_fields(df: pd.DataFrame) -> list[str]:
    present = set(df["field"].dropna().astype(str))
    return [f for f in FIELD_ORDER if f in present] + sorted(present - set(FIELD_ORDER))


def plot_reuse_boxplot(input_dir: Path, output_dir: Path, output_name: str) -> None:
    path = input_dir / "semantic_node_reuse_distribution.csv"
    if not path.exists():
        raise FileNotFoundError(f"Missing {path}. Run evaluate_kg_stats_corrected_final.py first.")

    df = pd.read_csv(path)
    df["vulnerability_count"] = pd.to_numeric(df["vulnerability_count"], errors="coerce")
    df = df.dropna(subset=["field", "vulnerability_count"])

    fields = ordered_fields(df)
    data = [df.loc[df["field"] == f, "vulnerability_count"].values for f in fields]
    labels = [FIELD_LABELS.get(f, f) for f in fields]

    fig, ax = plt.subplots(figsize=(7.2, 2.8))
    ax.boxplot(data, showfliers=True, widths=0.55)
    ax.set_xticks(range(1, len(fields) + 1))
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel("CVEs per semantic node")
    ax.set_title("Semantic Node Reuse Distribution")
    ax.grid(True, axis="y", linewidth=0.3, alpha=0.5)

    fig.tight_layout()
    pdf_path = output_dir / f"{output_name}.pdf"
    png_path = output_dir / f"{output_name}.png"
    fig.savefig(pdf_path, bbox_inches="tight")
    fig.savefig(png_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {pdf_path}")
    print(f"Saved {png_path}")


def plot_similarity_score_histogram(input_dir: Path, output_dir: Path, output_name: str) -> None:
    path = input_dir / "similarity_score_histogram.csv"
    if not path.exists():
        raise FileNotFoundError(f"Missing {path}. Run evaluate_kg_stats_corrected_final.py first.")

    df = pd.read_csv(path)
    df["score_bin"] = pd.to_numeric(df["score_bin"], errors="coerce")
    df["undirected_pair_count"] = pd.to_numeric(df["undirected_pair_count"], errors="coerce")
    df = df.dropna(subset=["field", "score_bin", "undirected_pair_count"])
    df = df[(df["score_bin"] >= 0.70) & (df["score_bin"] <= 1.00)].copy()

    fields = ordered_fields(df)

    fig, ax = plt.subplots(figsize=(7.2, 2.8))
    for field in fields:
        group = df[df["field"] == field].sort_values("score_bin")
        total = group["undirected_pair_count"].sum()
        if total == 0:
            continue
        y = group["undirected_pair_count"] / total
        ax.plot(group["score_bin"], y, marker="o", linewidth=1.1, markersize=3, label=field)

    ax.set_xlabel("Similarity score bin")
    ax.set_ylabel("Proportion of pairs")
    ax.set_title("Semantic Neighborhood Score Distribution")
    ax.set_xlim(0.70, 1.00)
    ax.grid(True, axis="y", linewidth=0.3, alpha=0.5)
    ax.legend(fontsize=6.5, ncol=4, frameon=False)

    fig.tight_layout()
    pdf_path = output_dir / f"{output_name}.pdf"
    png_path = output_dir / f"{output_name}.png"
    fig.savefig(pdf_path, bbox_inches="tight")
    fig.savefig(png_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {pdf_path}")
    print(f"Saved {png_path}")


def _load_component_summary(input_dir: Path) -> pd.DataFrame:
    path = input_dir / "semantic_component_summary.csv"
    if not path.exists():
        raise FileNotFoundError(f"Missing {path}. Run evaluate_kg_stats_corrected_final.py first.")

    df = pd.read_csv(path)
    required = {"field", "threshold", "component_count", "avg_component_size"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{path} is missing required columns: {sorted(missing)}")

    df["threshold"] = pd.to_numeric(df["threshold"], errors="coerce")
    df["component_count"] = pd.to_numeric(df["component_count"], errors="coerce")
    df["avg_component_size"] = pd.to_numeric(df["avg_component_size"], errors="coerce")
    df = df.dropna(subset=["field", "threshold", "component_count", "avg_component_size"])
    return df


def plot_component_count_vs_threshold(input_dir: Path, output_dir: Path, output_name: str) -> None:
    df = _load_component_summary(input_dir)
    fields = ordered_fields(df)

    fig, ax = plt.subplots(figsize=(7.2, 2.8))
    for field in fields:
        group = df[df["field"] == field].sort_values("threshold")
        ax.plot(group["threshold"], group["component_count"], marker="o", linewidth=1.2, markersize=3, label=field)

    ax.set_xlabel("Similarity threshold")
    ax.set_ylabel("Component count")
    ax.set_title("Component Count vs. Similarity Threshold")
    ax.set_xlim(0.845, 0.955)
    ax.grid(True, axis="y", linewidth=0.3, alpha=0.5)
    ax.legend(fontsize=6.5, ncol=4, frameon=False)

    fig.tight_layout()
    pdf_path = output_dir / f"{output_name}.pdf"
    png_path = output_dir / f"{output_name}.png"
    fig.savefig(pdf_path, bbox_inches="tight")
    fig.savefig(png_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {pdf_path}")
    print(f"Saved {png_path}")


def plot_avg_component_size_vs_threshold(input_dir: Path, output_dir: Path, output_name: str) -> None:
    df = _load_component_summary(input_dir)
    fields = ordered_fields(df)

    fig, ax = plt.subplots(figsize=(7.2, 2.8))
    for field in fields:
        group = df[df["field"] == field].sort_values("threshold")
        ax.plot(group["threshold"], group["avg_component_size"], marker="o", linewidth=1.2, markersize=3, label=field)

    ax.set_xlabel("Similarity threshold")
    ax.set_ylabel("Average component size")
    ax.set_title("Average Component Size vs. Similarity Threshold")
    ax.set_xlim(0.845, 0.955)
    ax.grid(True, axis="y", linewidth=0.3, alpha=0.5)
    ax.legend(fontsize=6.5, ncol=4, frameon=False)

    fig.tight_layout()
    pdf_path = output_dir / f"{output_name}.pdf"
    png_path = output_dir / f"{output_name}.png"
    fig.savefig(pdf_path, bbox_inches="tight")
    fig.savefig(png_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {pdf_path}")
    print(f"Saved {png_path}")


def main() -> None:
    args = parse_args()
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    plot_reuse_boxplot(input_dir, output_dir, args.reuse_output_name)
    plot_similarity_score_histogram(input_dir, output_dir, args.hist_output_name)
    plot_component_count_vs_threshold(input_dir, output_dir, args.component_count_output_name)
    plot_avg_component_size_vs_threshold(input_dir, output_dir, args.component_size_output_name)


if __name__ == "__main__":
    main()
