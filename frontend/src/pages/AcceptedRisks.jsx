import { useEffect, useState } from "react";
import {
  ChevronLeft,
  ChevronRight,
  X,
} from "lucide-react";

import { getAcceptedRisks } from "../services/api";


const PAGE_SIZE = 10;


function formatDate(value) {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "—";
  }

  return date.toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
}


function StatusBadge({ status }) {
  const value = status || "UNKNOWN";

  return (
    <span
      className={`accepted-risk-status ${
        value.toLowerCase()
      }`}
    >
      {value}
    </span>
  );
}


function AcceptedRiskDetails({ risk, onClose }) {
  if (!risk) {
    return null;
  }

  return (
    <div className="details-overlay">

      <div className="details-panel">

        <div className="details-header">

          <div>

            <div className="details-label">
              ACCEPTED RISK
            </div>

            <h2>
              {risk.accepted_risk_id || "Accepted Risk"}
            </h2>

          </div>

          <button
            className="close-button"
            onClick={onClose}
          >
            <X size={18} />
          </button>

        </div>


        {/* Summary */}

        <div className="details-summary">

          <div>
            <span>Status</span>

            <StatusBadge
              status={risk.status}
            />
          </div>


          <div>
            <span>Accepted By</span>

            <strong>
              {risk.accepted_by || "—"}
            </strong>
          </div>


          <div>
            <span>End Date</span>

            <strong>
              {formatDate(risk.end_date)}
            </strong>
          </div>

        </div>


        {/* Risk Information */}

        <div className="details-section">

          <div className="details-section-title">
            Risk Information
          </div>

          <div className="info-list">

            <div>
              <span>Accepted Risk ID</span>

              <strong>
                {risk.accepted_risk_id || "—"}
              </strong>
            </div>


            <div>
              <span>CVE</span>

              <strong>
                {risk.cve || "Not available"}
              </strong>
            </div>


            <div>
              <span>Vulnerability</span>

              <strong>
                {risk.vulnerability || "Not available"}
              </strong>
            </div>

          </div>

        </div>


        {/* Acceptance Details */}

        <div className="details-section">

          <div className="details-section-title">
            Acceptance Details
          </div>

          <div className="info-list">

            <div>
              <span>Accepted By</span>

              <strong>
                {risk.accepted_by || "—"}
              </strong>
            </div>


            <div>
              <span>Reason</span>

              <strong>
                {risk.reason || "No reason provided"}
              </strong>
            </div>


            <div>
              <span>Start Date</span>

              <strong>
                {formatDate(risk.start_date)}
              </strong>
            </div>


            <div>
              <span>End Date</span>

              <strong>
                {formatDate(risk.end_date)}
              </strong>
            </div>


            <div>
              <span>Status</span>

              <strong>
                {risk.status || "—"}
              </strong>
            </div>


            <div>
              <span>Created At</span>

              <strong>
                {formatDate(risk.created_at)}
              </strong>
            </div>

          </div>

        </div>

      </div>

    </div>
  );
}


export default function AcceptedRisks() {

  const [risks, setRisks] = useState([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState(null);

  const [selectedRisk, setSelectedRisk] =
    useState(null);

  const [page, setPage] =
    useState(1);


  useEffect(() => {

    async function loadAcceptedRisks() {

      try {

        const result =
          await getAcceptedRisks();

        setRisks(
          result.accepted_risks || []
        );

      } catch (err) {

        console.error(err);

        setError(
          "Unable to load accepted risks."
        );

      } finally {

        setLoading(false);

      }

    }

    loadAcceptedRisks();

  }, []);


  const totalPages =
    Math.max(
      1,
      Math.ceil(
        risks.length /
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


  const currentRisks =
    risks.slice(
      start,
      start + PAGE_SIZE
    );


  if (loading) {

    return (

      <div className="page">

        <div className="page-header">

          <div>

            <div className="eyebrow">
              RISK GOVERNANCE
            </div>

            <h1>
              Accepted Risks
            </h1>

            <p>
              Approved security exceptions
              and their validity periods
            </p>

          </div>

        </div>


        <div className="loading-card">
          Loading accepted risks...
        </div>

      </div>

    );

  }


  if (error) {

    return (

      <div className="page">

        <div className="page-header">

          <div>

            <div className="eyebrow">
              RISK GOVERNANCE
            </div>

            <h1>
              Accepted Risks
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
            RISK GOVERNANCE
          </div>

          <h1>
            Accepted Risks
          </h1>

          <p>
            Approved security exceptions
            with defined ownership and
            expiration dates
          </p>

        </div>

      </div>


      {/* Summary */}

      <div className="prioritization-summary">

        <span>

          Total accepted risks{" "}

          <strong>
            {risks.length}
          </strong>

        </span>


        <span>

          Page{" "}

          <strong>
            {currentPage}
          </strong>

          {" "}of{" "}

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
                  ID
                </th>

                <th>
                  CVE / Vulnerability
                </th>

                <th>
                  Accepted By
                </th>

                <th>
                  Reason
                </th>

                <th>
                  Start Date
                </th>

                <th>
                  End Date
                </th>

                <th>
                  Status
                </th>

              </tr>

            </thead>


            <tbody>

              {currentRisks.length === 0 ? (

                <tr>

                  <td
                    colSpan="7"
                    className="empty-table"
                  >
                    No accepted risks available.
                  </td>

                </tr>

              ) : (

                currentRisks.map(
                  (risk) => (

                    <tr
                      key={risk.id}
                      className="finding-row"
                      onClick={() =>
                        setSelectedRisk(
                          risk
                        )
                      }
                    >

                      <td>

                        <strong>
                          {risk.accepted_risk_id ||
                            "—"}
                        </strong>

                      </td>


                      <td>

                        <div className="vulnerability-cell">

                          <strong>
                            {risk.cve ||
                              "No CVE"}
                          </strong>

                          <span>
                            {risk.vulnerability ||
                              "Unnamed vulnerability"}
                          </span>

                        </div>

                      </td>


                      <td>

                        {risk.accepted_by ||
                          "—"}

                      </td>


                      <td>

                        <div
                          className="vulnerability-cell"
                        >

                          <span>
                            {risk.reason ||
                              "No reason provided"}
                          </span>

                        </div>

                      </td>


                      <td>

                        {formatDate(
                          risk.start_date
                        )}

                      </td>


                      <td>

                        {formatDate(
                          risk.end_date
                        )}

                      </td>


                      <td>

                        <StatusBadge
                          status={
                            risk.status
                          }
                        />

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
              .map(
                (pageNumber) => (

                  <button
                    key={pageNumber}
                    className={
                      pageNumber ===
                      currentPage
                        ? "page-number active"
                        : "page-number"
                    }
                    onClick={() =>
                      setPage(
                        pageNumber
                      )
                    }
                  >
                    {pageNumber}
                  </button>

                )
              )}

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


      {/* Details */}

      <AcceptedRiskDetails
        risk={selectedRisk}
        onClose={() =>
          setSelectedRisk(null)
        }
      />

    </div>

  );
}