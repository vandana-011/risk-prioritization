from src.database.db import get_connection


def determine_owner_team(vulnerability, cve):

    text = (
        f"{vulnerability or ''} "
        f"{cve or ''}"
    ).lower()


    if any(keyword in text for keyword in [
        "mysql",
        "postgresql",
        "database",
        "sql"
    ]):
        return "Database Team"


    if any(keyword in text for keyword in [
        "php",
        "phpmyadmin",
        "jquery",
        "xss",
        "sql injection",
        "web application",
        "cgi",
        "lfi",
        "rce"
    ]):
        return "Web Application Team"

    
    if any(keyword in text for keyword in [
        "apache",
        "tomcat",
        "samba",
        "ftp",
        "vsftpd",
        "proftpd",
        "ssh",
        "rlogin",
        "vnc",
        "ssl",
        "tls",
        "certificate",
        "operating system",
        "eol",
        "backdoor",
        "distcc",
        "ruby"
    ]):
        return "Infrastructure Team"

    
    return "Security Team"


def main():

    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            id,
            vulnerability,
            cve,
            ticket_id
        FROM findings
        WHERE ticket_id IS NOT NULL
        AND ticket_id != ''
    """)

    findings = cursor.fetchall()

    print(
        "Findings with tickets:",
        len(findings)
    )

    update_cursor = connection.cursor()

    update_query = """
        UPDATE findings
        SET owner_team = %s
        WHERE id = %s
    """

    updated = 0

    for finding in findings:

        owner_team = determine_owner_team(
            finding["vulnerability"],
            finding["cve"]
        )

        update_cursor.execute(
            update_query,
            (
                owner_team,
                finding["id"]
            )
        )

        updated += 1

        print(
            f"Finding {finding['id']} "
            f"→ Ticket #{finding['ticket_id']} "
            f"→ {owner_team}"
        )

    connection.commit()

    update_cursor.close()
    cursor.close()
    connection.close()

    print(
        "\nOwner assignment complete."
    )

    print(
        "Rows updated:",
        updated
    )


if __name__ == "__main__":
    main()