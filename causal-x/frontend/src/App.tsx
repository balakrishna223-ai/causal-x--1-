import { BrowserRouter, Route, Routes } from "react-router-dom";

import { CollectorsPage } from "./pages/CollectorsPage";
import { EgressProofPage } from "./pages/EgressProofPage";
import { IncidentPassportPage } from "./pages/IncidentPassportPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { LandingPage } from "./pages/LandingPage";
import { LoginPage } from "./pages/LoginPage";
import { MonitoringPage } from "./pages/MonitoringPage";
import { OverviewPage } from "./pages/OverviewPage";
import { SettingsPage } from "./pages/SettingsPage";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/home" element={<OverviewPage />} />
        <Route path="/overview" element={<OverviewPage />} />
        <Route path="/monitoring" element={<MonitoringPage />} />
        <Route path="/incidents" element={<IncidentsPage />} />
        <Route path="/incidents/:id" element={<IncidentPassportPage />} />
        <Route path="/privacy/egress" element={<EgressProofPage />} />
        <Route path="/collectors" element={<CollectorsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Routes>
    </BrowserRouter>
  );
}
