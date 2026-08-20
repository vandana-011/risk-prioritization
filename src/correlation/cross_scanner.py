import pandas as pd


def correlate_cross_scanner(df):

    df = df.copy()

    df["scanner_count"] = 1
    df["detected_by"] = df["scanner"].fillna("Unknown")
    df["cross_scanner"] = False

    cve_mask = (
        df["cve"].notna()
        & df["cve"].astype(str).str.strip().ne("")
    )

    if not cve_mask.any():
        return df

    cve_df = df[cve_mask].copy()
    non_cve_df = df[~cve_mask].copy()

    cve_df["_cve_normalized"] = (
        cve_df["cve"]
        .astype(str)
        .str.strip()
        .str.upper()
    )

    result_rows = []

    for cve, group in cve_df.groupby(
        "_cve_normalized",
        sort=False
    ):

        scanners = sorted(
            set(
                str(scanner).strip()
                for scanner in group["scanner"]
                if pd.notna(scanner)
                and str(scanner).strip()
            )
        )

        if len(scanners) <= 1:

            for _, row in group.iterrows():
                result_rows.append(row)

            continue

        row = group.iloc[0].copy()

        row["cve"] = cve
        row["scanner_count"] = len(scanners)
        row["detected_by"] = ", ".join(scanners)
        row["cross_scanner"] = True

        result_rows.append(row)

    result = pd.DataFrame(result_rows)

    if not non_cve_df.empty:
        result = pd.concat(
            [
                result,
                non_cve_df
            ],
            ignore_index=True
        )

    result = result.drop(
        columns=["_cve_normalized"],
        errors="ignore"
    )

    return result.reset_index(drop=True)


def get_cross_scanner_summary(df):

    cve_df = df[
        df["cve"].notna()
        & df["cve"].astype(str).str.strip().ne("")
    ].copy()

    if cve_df.empty:
        return pd.DataFrame(
            columns=[
                "cve",
                "scanner_count",
                "detected_by"
            ]
        )

    cve_df["cve"] = (
        cve_df["cve"]
        .astype(str)
        .str.strip()
        .str.upper()
    )

    summary = (
        cve_df
        .groupby("cve")
        .agg(
            scanner_count=(
                "scanner",
                "nunique"
            ),
            detected_by=(
                "scanner",
                lambda x: ", ".join(
                    sorted(
                        set(
                            str(scanner).strip()
                            for scanner in x
                            if pd.notna(scanner)
                            and str(scanner).strip()
                        )
                    )
                )
            )
        )
        .reset_index()
    )

    return summary[
        summary["scanner_count"] > 1
    ].sort_values(
        "scanner_count",
        ascending=False
    )