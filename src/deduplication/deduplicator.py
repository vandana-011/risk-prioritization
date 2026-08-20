import pandas as pd


def deduplicate_findings(df):

    df = df.copy()


    dedup_columns = [
        "scanner",
        "asset",
        "endpoint",
        "method",
        "parameter",
        "vulnerability",
        "cwe"
    ]


    available_columns = [
        column
        for column in dedup_columns
        if column in df.columns
    ]


    duplicate_mask = df.duplicated(
        subset=available_columns,
        keep="first"
    )

    duplicates = df[duplicate_mask].copy()

    deduplicated_df = df[
        ~duplicate_mask
    ].copy()


    deduplicated_df["duplicate_count"] = 1

    duplicate_counts = (
        df.groupby(available_columns, dropna=False)
        .size()
        .reset_index(name="duplicate_count")
    )

    deduplicated_df = deduplicated_df.drop(
        columns=["duplicate_count"],
        errors="ignore"
    )

    deduplicated_df = deduplicated_df.merge(
        duplicate_counts,
        on=available_columns,
        how="left"
    )

    return deduplicated_df, duplicates