import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  TicketCheck,
  TrendingDown,
} from "lucide-react";

import {
  useEffect,
  useMemo,
  useState,
} from "react";

import { getDashboard } from "../services/api";


function MetricCard({
  title,
  value,
  description,
  icon: Icon,
}) {
  return (
    <div className="dashboard-metric-card">

      <div className="dashboard-metric-icon">
        <Icon size={19} />
      </div>

      <div className="dashboard-metric-content">

        <span>
          {title}
        </span>

        <strong>
          {value}
        </strong>

        <small>
          {description}
        </small>

      </div>

    </div>
  );
}


function RiskBar({
  label,
  value,
  total,
}) {

  const percentage =
    total > 0
      ? Math.round(
          (value / total) * 100
        )
      : 0;


  return (
    <div className="risk-bar-row">

      <div className="risk-bar-label">

        <span>
          {label}
        </span>

        <strong>
          {value}
        </strong>

      </div>


      <div className="risk-bar-track">

        <div
          className={`risk-bar-fill ${label.toLowerCase()}`}
          style={{
            width: `${percentage}%`,
          }}
        />

      </div>


      <span className="risk-bar-percent">
        {percentage}%
      </span>

    </div>
  );
}


function getUniqueFindings(findings) {

  const seen = new Set();


  return findings.filter(
    (finding) => {

      const key = [
        finding.scanner,
        finding.asset,
        finding.endpoint,
        finding.method,
        finding.parameter,
        finding.vulnerability,
        finding.cwe,
      ]
        .map(
          (value) =>
            value ?? ""
        )
        .join("|");


      if (seen.has(key)) {
        return false;
      }


      seen.add(key);

      return true;

    }
  );
}


export default function Dashboard() {

  const [findings, setFindings] =
    useState([]);


  const [
    processingMetrics,
    setProcessingMetrics,
  ] = useState(null);


  const [dashboardData, setDashboardData] =
    useState({});


  const [loading, setLoading] =
    useState(true);


  const [error, setError] =
    useState(null);


  useEffect(() => {

    async function loadDashboard() {

      try {

        const result =
          await getDashboard();


        setFindings(
          result.findings || []
        );


        setProcessingMetrics(
          result.processing_metrics || {}
        );


        setDashboardData(
          result
        );


      } catch (err) {

        console.error(err);


        setError(
          "Unable to load dashboard data."
        );


      } finally {

        setLoading(false);

      }

    }


    loadDashboard();

  }, []);


  const uniqueFindings =
    useMemo(
      () =>
        getUniqueFindings(
          findings
        ),
      [findings]
    );




  const riskSummary =
    useMemo(() => {

      const levels =
        dashboardData?.risk_levels || {};

      return {

        CRITICAL:
          Number(
            levels.CRITICAL || 0
          ),

        HIGH:
          Number(
            levels.HIGH || 0
          ),

        MEDIUM:
          Number(
            levels.MEDIUM || 0
          ),

        LOW:
          Number(
            levels.LOW || 0
          ),

      };

    }, [dashboardData]);


  

  const prioritySummary =
    useMemo(() => {

      const priorities =
        dashboardData?.priorities || {};

      return {

        P1:
          Number(
            priorities.P1 || 0
          ),

        P2:
          Number(
            priorities.P2 || 0
          ),

        P3:
          Number(
            priorities.P3 || 0
          ),

        P4:
          Number(
            priorities.P4 || 0
          ),

      };

    }, [dashboardData]);


  

  const ticketSummary =
    useMemo(() => {

      return {

        defectDojo:
          Number(
            dashboardData?.defectdojo_tickets || 0
          ),

        github:
          Number(
            dashboardData?.github_issues || 0
          ),

      };

    }, [dashboardData]);


  /*
   * Scanner summary comes directly
   * from the backend.
   */

  const scannerSummary =
    useMemo(() => {

      const scanners =
        dashboardData?.scanners || {};

      return Object.entries(
        scanners
      ).sort(
        (a, b) =>
          b[1] - a[1]
      );

    }, [dashboardData]);


  const totalRisk =
    Object.values(
      riskSummary
    ).reduce(
      (sum, value) =>
        sum + value,
      0
    );


  /*
   * Dynamic pipeline metrics
   * coming from the backend.
   */

  const rawFindings =
    processingMetrics?.raw_findings
    ?? "—";


  const afterDeduplication =
    processingMetrics?.after_deduplication
    ?? "—";


  const duplicatesRemoved =
    processingMetrics?.duplicates_removed
    ?? "—";


  const deduplicationPercentage =
    processingMetrics?.deduplication_percentage
    ?? "—";


  const afterCorrelation =
    processingMetrics?.after_correlation
    ?? "—";


  const actionable =
    processingMetrics?.actionable
    ?? "—";


  const falsePositives =
    processingMetrics?.false_positives
    ?? "—";


  const acceptedRisks =
    processingMetrics?.accepted_risks
    ?? "—";


  if (loading) {

    return (

      <div className="page">

        <div className="page-header">

          <div>

            <div className="eyebrow">
              SECURITY ANALYTICS
            </div>

            <h1>
              Risk Prioritization Dashboard
            </h1>

            <p>
              Explainable vulnerability ranking
              and ticket-ready remediation output
            </p>

          </div>

        </div>


        <div className="loading-card">
          Loading dashboard data...
        </div>

      </div>

    );

  }


  if (error) {

    return (

      <div className="page">

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
            SECURITY ANALYTICS
          </div>

          <h1>
            Risk Prioritization Dashboard
          </h1>

          <p>
            Explainable vulnerability ranking
            and ticket-ready remediation output
          </p>

        </div>


        <div className="pipeline-connected">

          <span />

          Pipeline connected

        </div>

      </div>


      

      <div className="before-after-grid">


        {/* BEFORE */}

        <section className="before-after-card">

          <div className="before-after-header">

            <div>

              <span className="section-eyebrow">
                BEFORE
              </span>

              <h2>
                Scanner Findings
              </h2>

              <p>
                Raw findings received from
                security scanners
              </p>

            </div>


            <div className="before-icon">
              <Activity size={20} />
            </div>

          </div>


          <div className="before-metrics">


            <MetricCard
              title="Raw Findings"
              value={rawFindings}
              description="Scanner findings received"
              icon={Activity}
            />


            <MetricCard
              title="After Deduplication"
              value={afterDeduplication}
              description="Unique findings after deduplication"
              icon={CheckCircle2}
            />


            <MetricCard
              title="Duplicates Removed"
              value={duplicatesRemoved}
              description={
                `${deduplicationPercentage}% noise reduction`
              }
              icon={AlertTriangle}
            />


          </div>


          <div className="scanner-list">

            <div className="subsection-title">
              Scanner Distribution
            </div>


            {scannerSummary.length === 0 ? (

              <div className="empty-small">
                No scanner data available.
              </div>

            ) : (

              scannerSummary.map(
                ([scanner, count]) => (

                  <div
                    className="scanner-row"
                    key={scanner}
                  >

                    <span>
                      {scanner}
                    </span>

                    <strong>
                      {count}
                    </strong>

                  </div>

                )
              )

            )}

          </div>

        </section>


        {/* AFTER */}

        <section className="before-after-card">

          <div className="before-after-header">

            <div>

              <span className="section-eyebrow">
                AFTER
              </span>

              <h2>
                Prioritized Output
              </h2>

              <p>
                Explainable ranking prepared
                for remediation
              </p>

            </div>


            <div className="after-icon">
              <TrendingDown size={20} />
            </div>

          </div>


          <div className="before-metrics">


            <MetricCard
              title="After Correlation"
              value={afterCorrelation}
              description="Cross-scanner findings consolidated"
              icon={TrendingDown}
            />


            <MetricCard
              title="Actionable"
              value={actionable}
              description="Remaining remediation findings"
              icon={ShieldAlert}
            />


            <MetricCard
              title="Ticket Ready"
              value={
                ticketSummary.defectDojo +
                ticketSummary.github
              }
              description="Remediation outputs"
              icon={TicketCheck}
            />


          </div>


          <div className="scanner-list">

            <div className="subsection-title">
              Filtering Result
            </div>


            <div className="scanner-row">

              <span>
                False Positives
              </span>

              <strong>
                {falsePositives}
              </strong>

            </div>


            <div className="scanner-row">

              <span>
                Accepted Risks
              </span>

              <strong>
                {acceptedRisks}
              </strong>

            </div>


            <div className="scanner-row">

              <span>
                Actionable Findings
              </span>

              <strong>
                {actionable}
              </strong>

            </div>


            <div className="subsection-title">
              Priority Distribution
            </div>


            {[
              [
                "P1",
                prioritySummary.P1,
              ],

              [
                "P2",
                prioritySummary.P2,
              ],

              [
                "P3",
                prioritySummary.P3,
              ],

              [
                "P4",
                prioritySummary.P4,
              ],

            ].map(
              ([priority, count]) => (

                <div
                  className="priority-summary-row"
                  key={priority}
                >

                  <span
                    className={`priority-badge ${priority.toLowerCase()}`}
                  >
                    {priority}
                  </span>


                  <div className="priority-summary-track">

                    <div
                      className={`priority-summary-fill ${priority.toLowerCase()}`}
                      style={{
                        width:
                          totalRisk > 0
                            ? `${Math.round(
                                (
                                  count /
                                  totalRisk
                                ) *
                                100
                              )}%`
                            : "0%",
                      }}
                    />

                  </div>


                  <strong>
                    {count}
                  </strong>

                </div>

              )
            )}

          </div>

        </section>

      </div>


      

      <div className="dashboard-two-column">


        {/* Risk distribution */}

        <section className="dashboard-panel">

          <div className="panel-header">

            <div>

              <h2>
                Risk Distribution
              </h2>

              <p>
                Findings by calculated risk level
              </p>

            </div>

          </div>


          <div className="risk-bars">

            <RiskBar
              label="Critical"
              value={
                riskSummary.CRITICAL
              }
              total={totalRisk}
            />


            <RiskBar
              label="High"
              value={
                riskSummary.HIGH
              }
              total={totalRisk}
            />


            <RiskBar
              label="Medium"
              value={
                riskSummary.MEDIUM
              }
              total={totalRisk}
            />


            <RiskBar
              label="Low"
              value={
                riskSummary.LOW
              }
              total={totalRisk}
            />

          </div>

        </section>


        {/* Ticket output */}

        <section className="dashboard-panel">

          <div className="panel-header">

            <div>

              <h2>
                Ticket-Ready Output
              </h2>

              <p>
                Remediation work generated
                from prioritized findings
              </p>

            </div>

          </div>


          <div className="ticket-output-grid">

            <div className="ticket-output-card">

              <span>
                DefectDojo Tickets
              </span>

              <strong>
                {ticketSummary.defectDojo}
              </strong>

            </div>


            <div className="ticket-output-card">

              <span>
                GitHub Issues
              </span>

              <strong>
                {ticketSummary.github}
              </strong>

            </div>

          </div>


          <div className="dashboard-explainable">

            <div className="subsection-title">
              Explainable Ranking
            </div>


            <div className="explainable-list">

              <div>

                <strong>
                  CVSS
                </strong>

                <span>
                  Severity impact
                </span>

              </div>


              <div>

                <strong>
                  EPSS
                </strong>

                <span>
                  Exploit likelihood
                </span>

              </div>


              <div>

                <strong>
                  KEV
                </strong>

                <span>
                  Known exploitation
                </span>

              </div>


              <div>

                <strong>
                  Exploit
                </strong>

                <span>
                  Public exploit availability
                </span>

              </div>


              <div>

                <strong>
                  Confidence
                </strong>

                <span>
                  Scanner confidence
                </span>

              </div>


              <div>

                <strong>
                  Asset
                </strong>

                <span>
                  Business criticality
                </span>

              </div>

            </div>

          </div>

        </section>

      </div>


    </div>

  );

}