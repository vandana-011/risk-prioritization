import {
  LayoutDashboard,
  ListChecks,
  ShieldCheck,
  TicketCheck,
} from "lucide-react";

import {
  Navigate,
  NavLink,
  Route,
  Routes,
} from "react-router-dom";

import "./index.css";

import DashboardPage from "./pages/Dashboard";
import AcceptedRisksPage from "./pages/AcceptedRisks";
import PrioritizationPage from "./pages/Prioritization";
import TicketsPage from "./pages/Tickets";


function Sidebar() {

  const navigation = [

    {
      name: "Dashboard",
      path: "/",
      icon: LayoutDashboard,
    },

    {
      name: "Prioritization",
      path: "/prioritization",
      icon: ListChecks,
    },

    {
      name: "Accepted Risks",
      path: "/accepted-risks",
      icon: ShieldCheck,
    },

    {
      name: "Tickets",
      path: "/tickets",
      icon: TicketCheck,
    },

  ];


  return (

    <aside className="sidebar">

      <div className="brand">

        <div className="brand-icon">
          <ShieldCheck size={22} />
        </div>

        <div>

          <div className="brand-name">
            Risk Prioritization
          </div>

          <div className="brand-subtitle">
            Security Intelligence
          </div>

        </div>

      </div>


      <nav className="navigation">

        <div className="nav-section-title">
          WORKSPACE
        </div>


        {navigation.map((item) => {

          const Icon = item.icon;

          return (

            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === "/"}
              className={({ isActive }) =>
                `nav-link ${isActive ? "active" : ""}`
              }
            >

              <Icon size={18} />

              <span>
                {item.name}
              </span>

            </NavLink>

          );

        })}

      </nav>


      <div className="sidebar-bottom">

        <div className="pipeline-status">

          <div className="status-dot" />

          <div>

            <div className="status-title">
              Pipeline Ready
            </div>

            <div className="status-text">
              MySQL connected
            </div>

          </div>

        </div>

      </div>

    </aside>

  );

}


function Dashboard() {
  return <DashboardPage />;
}


function Prioritization() {
  return <PrioritizationPage />;
}


function AcceptedRisks() {
  return <AcceptedRisksPage />;
}


function Tickets() {
  return <TicketsPage />;
}


function App() {

  return (

    <div className="app">

      <Sidebar />

      <main className="main-content">

        <Routes>

          <Route
            path="/"
            element={<Dashboard />}
          />


          <Route
            path="/prioritization"
            element={<Prioritization />}
          />


          <Route
            path="/accepted-risks"
            element={<AcceptedRisks />}
          />


          <Route
            path="/tickets"
            element={<Tickets />}
          />


          <Route
            path="*"
            element={
              <Navigate
                to="/"
                replace
              />
            }
          />

        </Routes>

      </main>

    </div>

  );

}


export default App;