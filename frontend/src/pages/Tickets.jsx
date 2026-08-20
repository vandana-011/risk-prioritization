import { useEffect, useMemo, useState } from "react";
import {
  Search,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Ticket as TicketIcon,
  X,
} from "lucide-react";

import { getTickets } from "../services/api";


const PAGE_SIZE = 10;


const SLA_MAP = {
  P1: "24 hours",
  P2: "3 days",
  P3: "7 days",
  P4: "30 days",
};


function PriorityBadge({ priority }) {
  return (
    <span
      className={`priority-badge ${
        priority?.toLowerCase() || "unknown"
      }`}
    >
      {priority || "—"}
    </span>
  );
}


function TicketDetails({ ticket, onClose }) {
  if (!ticket) {
    return null;
  }

  const priority = ticket.priority;

  return (
    <div className="details-overlay">

      <div className="details-panel">

        <div className="details-header">

          <div>

            <div className="details-label">
              TICKET DETAILS
            </div>

            <h2>
              {ticket.vulnerability ||
                "Security finding"}
            </h2>

          </div>

          <button
            className="close-button"
            onClick={onClose}
          >
            <X size={18} />
          </button>

        </div>


        {/* Ticket summary */}

        <div className="details-summary">

          <div>

            <span>
              Priority
            </span>

            <PriorityBadge
              priority={priority}
            />

          </div>


          <div>

            <span>
              Owner
            </span>

            <strong>
              {ticket.owner_team ||
                "Unassigned"}
            </strong>

          </div>


          <div>

            <span>
              SLA
            </span>

            <strong>
              {SLA_MAP[priority] ||
                "—"}
            </strong>

          </div>

        </div>


        {/* Ticket information */}

        <div className="details-section">

          <div className="details-section-title">
            Ticket Information
          </div>


          <div className="ticket-ready">

            <div className="ticket-row">

              <span>
                DefectDojo Ticket
              </span>

              <strong>
                {ticket.ticket_id
                  ? `#${ticket.ticket_id}`
                  : "Not generated"}
              </strong>

            </div>


            <div className="ticket-row">

              <span>
                Ticket Status
              </span>

              <strong>
                {ticket.ticket_status ||
                  "—"}
              </strong>

            </div>


            <div className="ticket-row">

              <span>
                GitHub Issue
              </span>

              {ticket.github_issue_url ? (

                <a
                  href={
                    ticket.github_issue_url
                  }
                  target="_blank"
                  rel="noreferrer"
                  className="external-link"
                >
                  #{ticket.github_issue_id}
                  <ExternalLink size={14} />
                </a>

              ) : (

                <strong>
                  Not generated
                </strong>

              )}

            </div>

          </div>

        </div>


        {/* Finding information */}

        <div className="details-section">

          <div className="details-section-title">
            Finding Information
          </div>


          <div className="info-list">

            <div>
              <span>
                CVE
              </span>

              <strong>
                {ticket.cve ||
                  "Not available"}
              </strong>
            </div>


            <div>
              <span>
                CWE
              </span>

              <strong>
                {ticket.cwe ||
                  "Not available"}
              </strong>
            </div>


            <div>
              <span>
                Severity
              </span>

              <strong>
                {ticket.severity ||
                  "—"}
              </strong>
            </div>


            <div>
              <span>
                Risk Score
              </span>

              <strong>
                {ticket.risk_score ??
                  "—"}
              </strong>
            </div>


            <div>
              <span>
                Scanner
              </span>

              <strong>
                {ticket.scanner ||
                  "—"}
              </strong>
            </div>


            <div>
              <span>
                Asset
              </span>

              <strong>
                {ticket.asset ||
                  "—"}
              </strong>
            </div>

          </div>

        </div>


        {/* Reason */}

        {ticket.reason && (

          <div className="details-section">

            <div className="details-section-title">
              Prioritization Reason
            </div>

            <p className="details-description">
              {ticket.reason}
            </p>

          </div>

        )}


        {/* Links */}

        <div className="details-section">

          <div className="details-section-title">
            External Tickets
          </div>


          <div className="ticket-links">

            {ticket.github_issue_url && (

              <a
                href={
                  ticket.github_issue_url
                }
                target="_blank"
                rel="noreferrer"
                className="ticket-link-card"
              >

                <div>

                  <strong>
                    GitHub Issue
                  </strong>

                  <span>
                    View remediation issue
                  </span>

                </div>

                <ExternalLink size={16} />

              </a>

            )}


            {!ticket.github_issue_url && (
              <div className="ticket-link-card disabled">

                <div>

                  <strong>
                    GitHub Issue
                  </strong>

                  <span>
                    No GitHub issue generated
                  </span>

                </div>

              </div>
            )}

          </div>

        </div>

      </div>

    </div>
  );
}


export default function Tickets() {

  const [tickets, setTickets] =
    useState([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState(null);

  const [search, setSearch] =
    useState("");

  const [typeFilter, setTypeFilter] =
    useState("ALL");

  const [selectedTicket, setSelectedTicket] =
    useState(null);

  const [page, setPage] =
    useState(1);


  useEffect(() => {

    async function loadTickets() {

      try {

        const result =
          await getTickets();

        setTickets(
          result.tickets || []
        );

      } catch (err) {

        console.error(err);

        setError(
          "Unable to load tickets."
        );

      } finally {

        setLoading(false);

      }

    }

    loadTickets();

  }, []);


  const filteredTickets =
    useMemo(() => {

      const searchText =
        search
          .trim()
          .toLowerCase();


      return tickets.filter(
        (ticket) => {

          if (
            typeFilter === "DEFECTDOJO" &&
            !ticket.ticket_id
          ) {
            return false;
          }


          if (
            typeFilter === "GITHUB" &&
            !ticket.github_issue_url
          ) {
            return false;
          }


          if (!searchText) {
            return true;
          }


          return [

            ticket.cve,

            ticket.vulnerability,

            ticket.owner_team,

            ticket.scanner,

            ticket.asset,

            ticket.ticket_id,

            ticket.github_issue_id,

          ]
            .filter(Boolean)
            .some((value) =>
              String(value)
                .toLowerCase()
                .includes(searchText)
            );

        }
      );

    }, [
      tickets,
      search,
      typeFilter,
    ]);


  const totalPages =
    Math.max(
      1,
      Math.ceil(
        filteredTickets.length /
        PAGE_SIZE
      )
    );


  const currentPage =
    Math.min(
      page,
      totalPages
    );


  const start =
    (currentPage - 1) *
    PAGE_SIZE;


  const currentTickets =
    filteredTickets.slice(
      start,
      start + PAGE_SIZE
    );


  if (loading) {

    return (
      <div className="page">

        <div className="page-header">

          <div>

            <div className="eyebrow">
              REMEDIATION OUTPUT
            </div>

            <h1>
              Tickets
            </h1>

            <p>
              Ticket-ready security remediation
              with owners and SLAs
            </p>

          </div>

        </div>

        <div className="loading-card">
          Loading tickets...
        </div>

      </div>
    );
  }


  if (error) {

    return (
      <div className="page">

        <div className="page-header">

          <div>

            <h1>
              Tickets
            </h1>

          </div>

        </div>

        <div className="error-card">
          {error}
        </div>

      </div>
    );
  }


  return (
    <div className="page">

      {/* Header */}

      <div className="page-header">

        <div>

          <div className="eyebrow">
            REMEDIATION OUTPUT
          </div>

          <h1>
            Tickets
          </h1>

          <p>
            Ticket-ready remediation with
            owners, SLAs and external links
          </p>

        </div>

      </div>


      {/* Ticket summary */}

      <div className="ticket-stats-grid">

        <div className="ticket-stat-card">

          <div className="ticket-stat-icon">
            <TicketIcon size={19} />
          </div>

          <div>

            <span>
              Total Tickets
            </span>

            <strong>
              {tickets.length}
            </strong>

          </div>

        </div>


        <div className="ticket-stat-card">

          <div className="ticket-stat-icon">
            <TicketIcon size={19} />
          </div>

          <div>

            <span>
              DefectDojo
            </span>

            <strong>
              {
                tickets.filter(
                  (ticket) =>
                    ticket.ticket_id
                ).length
              }
            </strong>

          </div>

        </div>


        <div className="ticket-stat-card">

          <div className="ticket-stat-icon">
            <ExternalLink size={19} />
          </div>

          <div>

            <span>
              GitHub Issues
            </span>

            <strong>
              {
                tickets.filter(
                  (ticket) =>
                    ticket.github_issue_url
                ).length
              }
            </strong>

          </div>

        </div>


        <div className="ticket-stat-card">

          <div className="ticket-stat-icon">
            <TicketIcon size={19} />
          </div>

          <div>

            <span>
              P1 Tickets
            </span>

            <strong>
              {
                tickets.filter(
                  (ticket) =>
                    ticket.priority === "P1"
                ).length
              }
            </strong>

          </div>

        </div>

      </div>


      {/* Controls */}

      <div className="tickets-controls">

        <div className="search-box">

          <Search size={17} />

          <input
            type="text"
            placeholder="Search CVE, vulnerability, owner or ticket..."
            value={search}
            onChange={(event) => {
              setSearch(
                event.target.value
              );
              setPage(1);
            }}
          />

        </div>


        <div className="filter-group">

          {[
            "ALL",
            "DEFECTDOJO",
            "GITHUB",
          ].map((type) => (

            <button
              key={type}
              className={
                typeFilter === type
                  ? "filter-button active"
                  : "filter-button"
              }
              onClick={() => {
                setTypeFilter(type);
                setPage(1);
              }}
            >
              {type === "ALL"
                ? "All"
                : type === "DEFECTDOJO"
                ? "DefectDojo"
                : "GitHub"}
            </button>

          ))}

        </div>

      </div>


      {/* Summary */}

      <div className="prioritization-summary">

        <span>
          Showing{" "}

          <strong>
            {filteredTickets.length}
          </strong>{" "}

          tickets
        </span>


        <span>
          Page{" "}

          <strong>
            {currentPage}
          </strong>{" "}

          of{" "}

          <strong>
            {totalPages}
          </strong>
        </span>

      </div>


      {/* Table */}

      <div className="findings-table-card">

        <div className="findings-table-wrapper">

          <table className="findings-table">

            <thead>

              <tr>

                <th>
                  Priority
                </th>

                <th>
                  Vulnerability
                </th>

                <th>
                  CVE
                </th>

                <th>
                  Owner
                </th>

                <th>
                  SLA
                </th>

                <th>
                  DefectDojo
                </th>

                <th>
                  GitHub
                </th>

                <th>
                  Status
                </th>

              </tr>

            </thead>


            <tbody>

              {currentTickets.length === 0 ? (

                <tr>

                  <td
                    colSpan="8"
                    className="empty-table"
                  >
                    No tickets available.
                  </td>

                </tr>

              ) : (

                currentTickets.map(
                  (ticket, index) => (

                    <tr
                      key={
                        ticket.id ??
                        ticket.ticket_id ??
                        ticket.github_issue_id ??
                        index
                      }
                      className="finding-row"
                      onClick={() =>
                        setSelectedTicket(
                          ticket
                        )
                      }
                    >

                      <td>

                        <PriorityBadge
                          priority={
                            ticket.priority
                          }
                        />

                      </td>


                      <td>

                        <div className="vulnerability-cell">

                          <strong>
                            {
                              ticket.vulnerability ||
                              "Security finding"
                            }
                          </strong>

                          <span>
                            {ticket.scanner ||
                              "—"}
                          </span>

                        </div>

                      </td>


                      <td>

                        <span className="cve-text">
                          {ticket.cve ||
                            "—"}
                        </span>

                      </td>


                      <td>

                        <span className="owner-text">
                          {ticket.owner_team ||
                            "Unassigned"}
                        </span>

                      </td>


                      <td>

                        {SLA_MAP[
                          ticket.priority
                        ] || "—"}

                      </td>


                      <td>

                        {ticket.ticket_id ? (

                          <span className="ticket-id">
                            #{ticket.ticket_id}
                          </span>

                        ) : (

                          <span className="not-generated">
                            —
                          </span>

                        )}

                      </td>


                      <td>

                        {ticket.github_issue_url ? (

                          <a
                            href={
                              ticket.github_issue_url
                            }
                            target="_blank"
                            rel="noreferrer"
                            className="table-link"
                            onClick={(event) =>
                              event.stopPropagation()
                            }
                          >
                            #
                            {ticket.github_issue_id}
                            <ExternalLink
                              size={13}
                            />
                          </a>

                        ) : (

                          <span className="not-generated">
                            —
                          </span>

                        )}

                      </td>


                      <td>

                        <span className="ticket-status">
                          {ticket.ticket_status ||
                            "Open"}
                        </span>

                      </td>

                    </tr>

                  )
                )

              )}

            </tbody>

          </table>

        </div>


        {/* Pagination */}

        <div className="pagination">

          <button
            className="pagination-button"
            disabled={
              currentPage === 1
            }
            onClick={() =>
              setPage(
                (value) =>
                  Math.max(
                    1,
                    value - 1
                  )
              )
            }
          >
            <ChevronLeft size={16} />
            Previous
          </button>


          <div className="page-numbers">

            {Array.from(
              {
                length: totalPages,
              },
              (_, index) =>
                index + 1
            )
              .slice(
                Math.max(
                  0,
                  currentPage - 3
                ),
                currentPage + 2
              )
              .map((pageNumber) => (

                <button
                  key={pageNumber}
                  className={
                    pageNumber ===
                    currentPage
                      ? "page-number active"
                      : "page-number"
                  }
                  onClick={() =>
                    setPage(pageNumber)
                  }
                >
                  {pageNumber}
                </button>

              ))}

          </div>


          <button
            className="pagination-button"
            disabled={
              currentPage ===
              totalPages
            }
            onClick={() =>
              setPage(
                (value) =>
                  Math.min(
                    totalPages,
                    value + 1
                  )
              )
            }
          >
            Next
            <ChevronRight size={16} />
          </button>

        </div>

      </div>


      <TicketDetails
        ticket={selectedTicket}
        onClose={() =>
          setSelectedTicket(null)
        }
      />

    </div>
  );
}