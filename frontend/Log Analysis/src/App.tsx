import { Routes, Route } from "react-router-dom";
import Dashboard from "./pages/Dashboard";

function Landing() {
  return (
    <div>
      <h1>AI Log Threat Detection</h1>
      <p>This is the landing page</p>
    </div>
  );
}


function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/dashboard" element={<Dashboard />} />
    </Routes>
  );
}

export default App;