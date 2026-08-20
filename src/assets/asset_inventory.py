import pandas as pd


ASSET_CRITICALITY = {
    "http://localhost:3000": 3
}


def get_asset_criticality(asset):
    

    return ASSET_CRITICALITY.get(
        asset,
        3
    )


def enrich_asset_criticality(df):

    df["asset_criticality"] = df["asset"].apply(
        get_asset_criticality
    )

    return df