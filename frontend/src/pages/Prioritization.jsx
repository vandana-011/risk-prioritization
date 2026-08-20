import {
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Search,
  ShieldAlert,
  Sparkles,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { getFindings, getRiskExplanation } from "../services/api";

const PAGE_SIZE = 10;

const SLA_MAP = {
  P1: "24 hours",
  P2: "3 days",
  P3: "7 days",
  P4: "30 days",
};

function formatNumber(value, decimals = 2) {
  if (value === null || value === undefined) {
    return "—";
  }

  const number = Number(value);

  if (Number.isNaN(number)) {
    return "—";
  }

  return number.toFixed(decimals);
}

function formatBoolean(value) {
  if (value === true || value === 1) {
    return "Yes";
  }

  if (value === false || value === 0) {
    return "No";
  }

  return "—";
}

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

function RiskBadge({ level }) {
  return (
    <span
      className={`risk-badge ${
        level?.toLowerCase() || "unknown"
      }`}
    >
      {level || "—"}
    </span>
  );
}

function getRiskLevel(score) {
  if (score === null || score === undefined) {
    return "UNRANKED";
  }

  const value = Number(score);

  if (value >= 90) {
    return "CRITICAL";
  }

  if (value >= 70) {
    return "HIGH";
  }

  if (value >= 40) {
    return "MEDIUM";
  }

  return "LOW";
}

function AISection({ title, children }) {
  return (
    <div className="details-section">
      <div className="details-section-title">
        <Sparkles size={17} />
        {title}
      </div>

      <p className="details-description">
        {children || "No AI explanation available."}
      </p>
    </div>
  );
}

function FindingDetails({ finding, onClose }) {
  const [aiExplanation, setAiExplanation] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState(null);

  useEffect(() => {
    if (!finding) {
      return;
    }

    let cancelled = false;

    async function loadAIExplanation() {
      setAiLoading(true);

      try {
        const result = await getRiskExplanation(finding);

        if (!cancelled) {
          setAiExplanation(result);
          setAiError(null);
        }
      } catch (error) {
        console.error(error);

        if (!cancelled) {
          setAiError(
            "Unable to generate AI risk explanation."
          );
          setAiExplanation(null);
        }
      } finally {
        if (!cancelled) {
          setAiLoading(false);
        }
      }
    }

    loadAIExplanation();

    return () => {
      cancelled = true;
    };
  }, [finding]);

  if (!finding) {
    return null;
  }

  const riskLevel = getRiskLevel(
    finding.risk_score
  );

  

  return (
    <div className="details-overlay">
      <div className="details-panel">

        <div className="details-header">
          <div>
            <div className="details-label">
              FINDING DETAILS
            </div>

            <h2>
              {finding.vulnerability ||
                "Unnamed vulnerability"}
            </h2>
          </div>

          <button
            className="close-button"
            onClick={onClose}
          >
            <X size={18} />
          </button>
        </div>

        <div className="details-summary">

          <div>
            <span>Priority</span>
            <PriorityBadge
              priority={finding.priority}
            />
          </div>

          <div>
            <span>Risk Level</span>
            <RiskBadge
              level={riskLevel}
            />
          </div>

          <div>
            <span>Risk Score</span>
            <strong>
              {formatNumber(
                finding.risk_score
              )}
            </strong>
          </div>

        </div>

        <div className="details-section">

          <div className="details-section-title">
            <ShieldAlert size={17} />
            Why was this prioritized?
          </div>

          <div className="factor-grid">

            <div className="factor">
              <span>CVSS</span>
              <strong>
                {formatNumber(finding.cvss)}
              </strong>
              <small>
                Severity impact
              </small>
            </div>

            <div className="factor">
              <span>EPSS</span>
              <strong>
                {formatNumber(
                  finding.epss,
                  5
                )}
              </strong>
              <small>
                Exploit likelihood
              </small>
            </div>

            <div className="factor">
              <span>KEV</span>
              <strong>
                {formatBoolean(
                  finding.kev
                )}
              </strong>
              <small>
                Known exploitation
              </small>
            </div>

            <div className="factor">
              <span>Public Exploit</span>
              <strong>
                {formatBoolean(
                  finding.exploit_available
                )}
              </strong>
              <small>
                Exploit availability
              </small>
            </div>

            <div className="factor">
              <span>Confidence</span>
              <strong>
                {finding.confidence ?? "—"}
              </strong>
              <small>
                Scanner confidence
              </small>
            </div>

            <div className="factor">
              <span>Asset Criticality</span>
              <strong>
                {finding.asset_criticality ?? "—"}
              </strong>
              <small>
                Business importance
              </small>
            </div>

          </div>

        </div>

        <div className="details-section">

          <div className="details-section-title">
            Vulnerability Information
          </div>

          <div className="info-list">

            <div>
              <span>CVE</span>
              <strong>
                {finding.cve ||
                  "Not available"}
              </strong>
            </div>

            <div>
              <span>CWE</span>
              <strong>
                {finding.cwe ||
                  "Not available"}
              </strong>
            </div>

            <div>
              <span>Scanner</span>
              <strong>
                {finding.detected_by ||
                  finding.scanner ||
                  "—"}
              </strong>
            </div>

            <div>
              <span>Scanner Count</span>
              <strong>
                {finding.scanner_count ??
                  "—"}
              </strong>
            </div>

            <div>
              <span>Cross Scanner</span>
              <strong>
                {finding.cross_scanner
                  ? "Yes"
                  : "No"}
              </strong>
            </div>

            <div>
              <span>Asset</span>
              <strong>
                {finding.asset || "—"}
              </strong>
            </div>

            <div>
              <span>Endpoint</span>
              <strong>
                {finding.endpoint || "—"}
              </strong>
            </div>

          </div>

        </div>

        <div className="details-section">

          <div className="details-section-title">
            <Sparkles size={17} />
            AI Risk Analysis
          </div>

          {aiLoading && (
            <div className="loading-card">
              AI is analyzing this risk...
            </div>
          )}

          {aiError && (
            <div className="error-card">
              {aiError}
            </div>
          )}

          {!aiLoading &&
            !aiError &&
            aiExplanation && (
              <>
                <AISection title="Why is this a risk?">
                  {aiExplanation.why_it_is_risk}
                </AISection>

                <AISection title="Potential Impact">
                  {aiExplanation.potential_impact}
                </AISection>

                <AISection title="Why this priority?">
                  {aiExplanation.why_this_priority}
                </AISection>

                <AISection title="How to mitigate">
                  {aiExplanation.mitigation}
                </AISection>

                <AISection title="Recommended Action">
                  {aiExplanation.recommended_action}
                </AISection>
              </>
            )}

        </div>

        {finding.description && (
          <div className="details-section">

            <div className="details-section-title">
              Description
            </div>

            <p className="details-description">
              {finding.description}
            </p>

          </div>
        )}

        {finding.solution && (
          <div className="details-section">

            <div className="details-section-title">
              Scanner Remediation
            </div>

            <p className="details-description">
              {finding.solution}
            </p>

          </div>
        )}

      </div>
    </div>
  );
}

export default function Prioritization() {

  const [findings, setFindings] =
    useState([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState(null);

  const [search, setSearch] =
    useState("");

  const [priorityFilter, setPriorityFilter] =
    useState("ALL");

  const [selectedFinding, setSelectedFinding] =
    useState(null);

  const [page, setPage] =
    useState(1);

  useEffect(() => {

    async function loadFindings() {

      try {

        const result =
          await getFindings();

        setFindings(
          result.findings || []
        );

      } catch (err) {

        console.error(err);

        setError(
          "Unable to load findings."
        );

      } finally {

        setLoading(false);

      }
    }

    loadFindings();

  }, []);

  const filteredFindings =
    useMemo(() => {

      const searchText =
        search
          .trim()
          .toLowerCase();

      return findings

        .filter((finding) => {

          if (
            priorityFilter !== "ALL" &&
            finding.priority !== priorityFilter
          ) {
            return false;
          }

          if (!searchText) {
            return true;
          }

          return [

            finding.cve,

            finding.vulnerability,

            finding.scanner,

            finding.detected_by,

            finding.asset,

            finding.owner_team,

          ]
            .filter(Boolean)
            .some((value) =>
              String(value)
                .toLowerCase()
                .includes(searchText)
            );

        })

        .sort(
          (a, b) =>
            Number(b.risk_score || 0) -
            Number(a.risk_score || 0)
        );

    }, [
      findings,
      priorityFilter,
      search,
    ]);

  const totalPages =
    Math.max(
      1,
      Math.ceil(
        filteredFindings.length /
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

  const currentFindings =
    filteredFindings.slice(
      start,
      start + PAGE_SIZE
    );

  if (loading) {

    return (
      <div className="page">

        <div className="page-header">

          <div>

            <div className="eyebrow">
              RISK ENGINE
            </div>

            <h1>
              Prioritization
            </h1>

            <p>
              Explainable vulnerability ranking
              for remediation
            </p>

          </div>

        </div>

        <div className="loading-card">
          Loading prioritized findings...
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
              Prioritization
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

      <div className="page-header">

        <div>

          <div className="eyebrow">
            RISK ENGINE
          </div>

          <h1>
            Prioritization
          </h1>

          <p>
            Explainable vulnerability ranking
            and ticket-ready remediation
          </p>

        </div>

      </div>

      <div className="priority-controls">

        <div className="search-box">

          <Search size={17} />

          <input
            type="text"
            placeholder="Search CVE, vulnerability, scanner or owner..."
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setPage(1);
            }}
          />

        </div>

        <div className="filter-group">

          {[
            "ALL",
            "P1",
            "P2",
            "P3",
            "P4",
          ].map((priority) => (

            <button
              key={priority}
              className={
                priorityFilter === priority
                  ? "filter-button active"
                  : "filter-button"
              }
              onClick={() => {
                setPriorityFilter(priority);
                setPage(1);
              }}
            >
              {priority === "ALL"
                ? "All"
                : priority}
            </button>

          ))}

        </div>

      </div>

      <div className="prioritization-summary">

        <span>
          Showing{" "}

          <strong>
            {filteredFindings.length}
          </strong>{" "}

          prioritized findings
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

      <div className="findings-table-card">

        <div className="findings-table-wrapper">

          <table className="findings-table">

            <thead>

              <tr>

                <th>
                  Priority
                </th>

                <th>
                  Risk
                </th>

                <th>
                  Vulnerability
                </th>

                <th>
                  CVE
                </th>

                <th>
                  Scanner
                </th>

                <th>
                  Owner
                </th>

                <th>
                  SLA
                </th>

                <th>
                  Ticket
                </th>

              </tr>

            </thead>

            <tbody>

              {currentFindings.length === 0 ? (

                <tr>

                  <td
                    colSpan="8"
                    className="empty-table"
                  >
                    No findings available.
                  </td>

                </tr>

              ) : (

                currentFindings.map(
                  (finding) => {

                    const riskLevel =
                      getRiskLevel(
                        finding.risk_score
                      );

                    return (

                      <tr
                        key={finding.id}
                        onClick={() =>
                          setSelectedFinding(
                            finding
                          )
                        }
                        className="finding-row"
                      >

                        <td>

                          <PriorityBadge
                            priority={
                              finding.priority
                            }
                          />

                        </td>

                        <td>

                          <div className="risk-score">

                            <strong>
                              {formatNumber(
                                finding.risk_score
                              )}
                            </strong>

                            <RiskBadge
                              level={riskLevel}
                            />

                          </div>

                        </td>

                        <td>

                          <div className="vulnerability-cell">

                            <strong>
                              {
                                finding.vulnerability ||
                                "Unnamed vulnerability"
                              }
                            </strong>

                            <span>
                              {finding.asset ||
                                "No asset"}
                            </span>

                          </div>

                        </td>

                        <td>

                          <span className="cve-text">
                            {finding.cve ||
                              "—"}
                          </span>

                        </td>

                        <td>

                          {finding.detected_by ||
                            finding.scanner ||
                            "—"}

                        </td>

                        <td>

                          <span className="owner-text">

                            {finding.owner_team ||
                              "Unassigned"}

                          </span>

                        </td>

                        <td>

                          {SLA_MAP[
                            finding.priority
                          ] || "—"}

                        </td>

                        <td>

                          {finding.github_issue_url ? (

                            <a
                              href={
                                finding.github_issue_url
                              }
                              target="_blank"
                              rel="noreferrer"
                              className="table-link"
                              onClick={(event) =>
                                event.stopPropagation()
                              }
                            >
                              GitHub

                              <ExternalLink
                                size={13}
                              />
                            </a>

                          ) : finding.ticket_id ? (

                            <span className="ticket-id">
                              #{finding.ticket_id}
                            </span>

                          ) : (

                            <span className="not-generated">
                              —
                            </span>

                          )}

                        </td>

                      </tr>

                    );

                  }
                )

              )}

            </tbody>

          </table>

        </div>

        <div className="pagination">

          <button
            className="pagination-button"
            disabled={currentPage === 1}
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
                    pageNumber === currentPage
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
              currentPage === totalPages
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

      <FindingDetails
        finding={selectedFinding}
        onClose={() =>
          setSelectedFinding(null)
        }
      />

    </div>
  );
}