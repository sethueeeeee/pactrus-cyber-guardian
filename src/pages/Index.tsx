import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Shield } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "@/contexts/AuthContext";
import { LogOut } from "lucide-react";

const Index = () => {
  const { logout } = useAuth();
  const [alerts, setAlerts] = useState([
    {
      id: 1,
      title: "Potential Phishing Attack",
      description: "Detected suspicious email activity targeting multiple users.",
      severity: "High",
      status: "Open",
    },
    {
      id: 2,
      title: "Unusual Network Traffic",
      description: "Observed a spike in outbound traffic from server X.",
      severity: "Medium",
      status: "Investigating",
    },
    {
      id: 3,
      title: "Unauthorized Access Attempt",
      description: "Failed login attempts detected from an unknown IP address.",
      severity: "Low",
      status: "Resolved",
    },
  ]);

  const handleLogout = () => {
    logout();
    toast.success("Logged out successfully");
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Fixed Header */}
      <header className="fixed top-0 left-0 right-0 bg-white border-b border-gray-200 z-50 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-blue-600 mr-3" />
              <h1 className="text-2xl font-bold text-gray-900">Pactrus</h1>
            </div>
            
            <nav className="hidden md:flex space-x-8">
              <Link to="/" className="text-blue-600 font-medium border-b-2 border-blue-600 pb-1">
                Dashboard
              </Link>
              <Link to="/rules" className="text-gray-600 hover:text-gray-900 transition-colors">
                Security Rules
              </Link>
              <Link to="/alerts" className="text-gray-600 hover:text-gray-900 transition-colors">
                Alerts
              </Link>
              <Link to="/ml-suggestions" className="text-gray-600 hover:text-gray-900 transition-colors">
                ML Suggestions
              </Link>
              <Link to="/attack-patterns" className="text-gray-600 hover:text-gray-900 transition-colors">
                Attack Patterns
              </Link>
            </nav>

            <Button 
              onClick={handleLogout}
              variant="outline"
              size="sm"
              className="flex items-center gap-2"
            >
              <LogOut className="h-4 w-4" />
              Logout
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="pt-16">
        <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
          {/* Dashboard Content */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {/* Example Card */}
            <div className="bg-white shadow-md rounded-lg p-4">
              <h2 className="text-lg font-semibold text-gray-900 mb-2">
                System Status
              </h2>
              <p className="text-gray-600">All systems operational.</p>
            </div>

            {/* Alerts Card */}
            <div className="bg-white shadow-md rounded-lg p-4">
              <h2 className="text-lg font-semibold text-gray-900 mb-2">
                Recent Alerts
              </h2>
              <ul>
                {alerts.map((alert) => (
                  <li key={alert.id} className="py-2 border-b border-gray-200">
                    <div className="flex justify-between items-center">
                      <div>
                        <h3 className="text-md font-medium text-gray-800">
                          {alert.title}
                        </h3>
                        <p className="text-sm text-gray-600">{alert.description}</p>
                      </div>
                      <span className="px-2 py-1 bg-red-100 text-red-600 rounded-full text-xs font-semibold">
                        {alert.severity}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            </div>

            {/* Quick Actions Card */}
            <div className="bg-white shadow-md rounded-lg p-4">
              <h2 className="text-lg font-semibold text-gray-900 mb-2">
                Quick Actions
              </h2>
              <div className="mt-4 space-y-2">
                <Button>Run Scan</Button>
                <Button variant="secondary">Update Rules</Button>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Index;
