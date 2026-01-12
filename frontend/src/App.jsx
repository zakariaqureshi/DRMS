import React from "react";
import "./App.css";
import DRMSDashboard from "./components/DRMSDashboard";
import SideNav from "./components/SideNav";

function App() {
  return (
    <div className="with-sidenav">
      <SideNav />
      <DRMSDashboard />
    </div>
  );
}

export default App;
