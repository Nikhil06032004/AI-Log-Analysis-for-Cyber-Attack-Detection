import { Routes, Route, Navigate } from "react-router-dom";
import { AnalysisProvider } from "./context/AnalysisContext";
import AppLayout    from "./components/layout/AppLayout";
import Dashboard    from "./pages/Dashboard";
import Threats      from "./pages/Threats";
import LogExplorer  from "./pages/LogExplorer";
import NetworkMap   from "./pages/NetworkMap";
import Analytics    from "./pages/Analytics";

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
        </Route>
      </Routes>
    </AnalysisProvider>
  );
}

export default App;
