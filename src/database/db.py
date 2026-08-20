import os
from datetime import datetime

import mysql.connector
import pandas as pd
from dotenv import load_dotenv

load_dotenv()


def get_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", 3306)),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )


def create_findings_table():
    connection = get_connection()
    cursor = connection.cursor()

    query = """
    CREATE TABLE IF NOT EXISTS findings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        scan_id INT,
        scanner VARCHAR(50),
        detected_by VARCHAR(500),
        scanner_count INT,
        cross_scanner BOOLEAN,
        asset VARCHAR(500),
        endpoint VARCHAR(1000),
        method VARCHAR(20),
        parameter VARCHAR(500),
        attack TEXT,
        vulnerability VARCHAR(500),
        severity VARCHAR(50),
        confidence INT,
        cwe VARCHAR(50),
        evidence TEXT,
        description TEXT,
        solution TEXT,
        cve VARCHAR(50),
        cvss FLOAT,
        epss FLOAT,
        kev BOOLEAN,
        exploit_available BOOLEAN,
        asset_criticality INT,
        risk_score FLOAT,
        priority VARCHAR(20),
        status VARCHAR(50),
        reason TEXT,
        reviewer VARCHAR(100),
        review_date DATETIME,
        ticket_id VARCHAR(100),
        ticket_status VARCHAR(100),
        owner_team VARCHAR(100),
        first_seen DATETIME,
        last_seen DATETIME,
        classification VARCHAR(50),
        classification_confidence FLOAT,
        classification_reason TEXT
    )
    """

    cursor.execute(query)
    connection.commit()

    cursor.close()
    connection.close()

    print("Findings table ready.")


def create_scan_runs_table():
    connection = get_connection()
    cursor = connection.cursor()

    query = """
    CREATE TABLE IF NOT EXISTS scan_runs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        scanner VARCHAR(50),
        target VARCHAR(1000),
        started_at DATETIME,
        completed_at DATETIME,
        total_findings INT
    )
    """

    cursor.execute(query)
    connection.commit()

    cursor.close()
    connection.close()

    print("Scan runs table ready.")


def create_scan_run(scanner, target, total_findings):
    connection = get_connection()
    cursor = connection.cursor()

    now = datetime.now()

    query = """
    INSERT INTO scan_runs (
        scanner,
        target,
        started_at,
        completed_at,
        total_findings
    )
    VALUES (%s, %s, %s, %s, %s)
    """

    values = (
        scanner,
        target,
        now,
        now,
        int(total_findings)
    )

    cursor.execute(query, values)

    scan_id = cursor.lastrowid

    connection.commit()

    cursor.close()
    connection.close()

    print(f"Scan created: {scan_id}")

    return scan_id



def create_processing_metrics_table():

    connection = get_connection()
    cursor = connection.cursor()

    query = """
    CREATE TABLE IF NOT EXISTS processing_metrics (

        id INT AUTO_INCREMENT PRIMARY KEY,

        scan_id INT NOT NULL,

        raw_findings INT NOT NULL,

        after_deduplication INT NOT NULL,

        duplicates_removed INT NOT NULL,

        deduplication_percentage FLOAT NOT NULL,

        after_correlation INT NOT NULL,

        false_positives INT NOT NULL,

        accepted_risks INT NOT NULL,

        actionable INT NOT NULL,

        created_at DATETIME NOT NULL,

        FOREIGN KEY (scan_id)
            REFERENCES scan_runs(id)
            ON DELETE CASCADE
    )
    """

    cursor.execute(query)

    connection.commit()

    cursor.close()
    connection.close()

    print("Processing metrics table ready.")


def insert_processing_metrics(
    scan_id,
    raw_findings,
    after_deduplication,
    duplicates_removed,
    deduplication_percentage,
    after_correlation,
    false_positives,
    accepted_risks,
    actionable
):

    connection = get_connection()
    cursor = connection.cursor()

    query = """
    INSERT INTO processing_metrics (
        scan_id,
        raw_findings,
        after_deduplication,
        duplicates_removed,
        deduplication_percentage,
        after_correlation,
        false_positives,
        accepted_risks,
        actionable,
        created_at
    )
    VALUES (
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s
    )
    """

    values = (
        int(scan_id),
        int(raw_findings),
        int(after_deduplication),
        int(duplicates_removed),
        float(deduplication_percentage),
        int(after_correlation),
        int(false_positives),
        int(accepted_risks),
        int(actionable),
        datetime.now()
    )

    cursor.execute(
        query,
        values
    )

    connection.commit()

    cursor.close()
    connection.close()

    print("Processing metrics inserted.")


def clean_value(value):

    if pd.isna(value):
        return None

    if isinstance(value, float):

        if pd.isna(value):
            return None

    return value


def insert_findings(df):

    connection = get_connection()
    cursor = connection.cursor()

    query = """
    INSERT INTO findings (
        scan_id,
        scanner,
        detected_by,
        scanner_count,
        cross_scanner,
        asset,
        endpoint,
        method,
        parameter,
        attack,
        vulnerability,
        severity,
        confidence,
        cwe,
        evidence,
        description,
        solution,
        cve,
        cvss,
        epss,
        kev,
        exploit_available,
        asset_criticality,
        risk_score,
        priority,
        status,
        reason,
        reviewer,
        review_date,
        ticket_id,
        ticket_status,
        owner_team,
        first_seen,
        last_seen,
        classification,
        classification_confidence,
        classification_reason
    )
    VALUES (
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s,
        %s, %s
    )
    """

    inserted = 0

    for index, row in df.iterrows():

        values = (
            clean_value(row.get("scan_id")),
            clean_value(row.get("scanner")),
            clean_value(row.get("detected_by")),
            clean_value(row.get("scanner_count")),
            clean_value(row.get("cross_scanner")),
            clean_value(row.get("asset")),
            clean_value(row.get("endpoint")),
            clean_value(row.get("method")),
            clean_value(row.get("parameter")),
            clean_value(row.get("attack")),
            clean_value(row.get("vulnerability")),
            clean_value(row.get("severity")),
            clean_value(row.get("confidence")),
            clean_value(row.get("cwe")),
            clean_value(row.get("evidence")),
            clean_value(row.get("description")),
            clean_value(row.get("solution")),
            clean_value(row.get("cve")),
            clean_value(row.get("cvss")),
            clean_value(row.get("epss")),
            clean_value(row.get("kev")),
            clean_value(row.get("exploit_available")),
            clean_value(row.get("asset_criticality")),
            clean_value(row.get("risk_score")),
            clean_value(row.get("priority")),
            clean_value(row.get("status")),
            clean_value(row.get("reason")),
            clean_value(row.get("reviewer")),
            clean_value(row.get("review_date")),
            clean_value(row.get("ticket_id")),
            clean_value(row.get("ticket_status")),
            clean_value(row.get("owner_team")),
            clean_value(row.get("first_seen")),
            clean_value(row.get("last_seen")),
            clean_value(row.get("classification")),
            clean_value(row.get("classification_confidence")),
            clean_value(row.get("classification_reason"))
        )

        try:

            cursor.execute(
                query,
                values
            )

            inserted += 1

        except Exception as e:

            print()
            print("===== MYSQL INSERT ERROR =====")
            print("DataFrame row:", index)
            print(
                "Vulnerability:",
                row.get("vulnerability")
            )
            print(
                "CVE:",
                row.get("cve")
            )
            print(
                "Values:",
                values
            )
            print(
                "Number of values:",
                len(values)
            )
            print(
                "Error:",
                e
            )

            connection.rollback()

            cursor.close()
            connection.close()

            raise

    connection.commit()

    cursor.close()
    connection.close()

    print(
        f"{inserted} findings inserted into MySQL."
    )


def create_accepted_risks_table():

    connection = get_connection()
    cursor = connection.cursor()

    query = """
    CREATE TABLE IF NOT EXISTS accepted_risks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        accepted_risk_id VARCHAR(50) NOT NULL UNIQUE,
        cve VARCHAR(50),
        vulnerability VARCHAR(500),
        reason TEXT NOT NULL,
        accepted_by VARCHAR(100) NOT NULL,
        start_date DATE NOT NULL,
        end_date DATE NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
        created_at DATETIME NOT NULL
    )
    """

    cursor.execute(query)
    connection.commit()

    cursor.close()
    connection.close()

    print("Accepted risks table ready.")


def insert_accepted_risk(
    accepted_risk_id,
    cve,
    vulnerability,
    reason,
    accepted_by,
    start_date,
    end_date
):

    connection = get_connection()
    cursor = connection.cursor()

    query = """
    INSERT INTO accepted_risks (
        accepted_risk_id,
        cve,
        vulnerability,
        reason,
        accepted_by,
        start_date,
        end_date,
        status,
        created_at
    )
    VALUES (
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s
    )
    """

    now = datetime.now()

    values = (
        accepted_risk_id,
        cve,
        vulnerability,
        reason,
        accepted_by,
        start_date,
        end_date,
        "ACTIVE",
        now
    )

    cursor.execute(
        query,
        values
    )

    connection.commit()

    cursor.close()
    connection.close()

    print(
        f"Accepted risk {accepted_risk_id} inserted."
    )