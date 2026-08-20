def classify_finding(df, index, status, reason, reviewer):
   

    allowed_statuses = [
        "OPEN",
        "FALSE_POSITIVE",
        "ACCEPTED_RISK"
    ]

    if status not in allowed_statuses:
        raise ValueError(
            f"Invalid status. Choose from: {allowed_statuses}"
        )

    df.loc[index, "status"] = status
    df.loc[index, "reason"] = reason
    df.loc[index, "reviewer"] = reviewer

    return df