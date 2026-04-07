import { Routes, Route, Navigate } from "react-router-dom";
import { AnalysisProvider } from "./context/AnalysisContext";
import AppLayout    from "./components/layout/AppLayout";
import Dashboard    from "./pages/Dashboard";
import Threats      from "./pages/Threats";
import LogExplorer  from "./pages/LogExplorer";
import NetworkMap   from "./pages/NetworkMap";
import Analytics    from "./pages/Analytics";
import SIEMRules      from "./pages/SIEMRules";
import AIModel        from "./pages/AIModel";
import Settings       from "./pages/Settings";
import SystemMonitor  from "./pages/SystemMonitor";

function App() {
  return (
    <AnalysisProvider>
      <Routes>
        <Route element={<AppLayout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Dashboard />}   />
          <Route path="/threats"   element={<Threats />}     />
          <Route path="/logs"      element={<LogExplorer />} />
          <Route path="/network"   element={<NetworkMap />}  />
          <Route path="/analytics" element={<Analytics />}   />
          <Route path="/siem"           element={<SIEMRules />}      />
          <Route path="/system-monitor" element={<SystemMonitor />}  />
          <Route path="/ai-model"       element={<AIModel />}        />
          <Route path="/settings"       element={<Settings />}       />
        </Route>
      </Routes>
    </AnalysisProvider>
  );
}

export default App;
