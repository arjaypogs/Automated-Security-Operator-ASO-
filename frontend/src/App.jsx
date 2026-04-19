import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import NewScan from "./pages/NewScan";
import ScanDetail from "./pages/ScanDetail";
import Reports from "./pages/Reports";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="scans/new" element={<NewScan />} />
        <Route path="scans/:id" element={<ScanDetail />} />
        <Route path="reports" element={<Reports />} />
      </Route>
    </Routes>
  );
}
