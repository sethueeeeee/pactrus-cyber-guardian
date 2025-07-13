
import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, LogOut, User, Activity, AlertTriangle, TrendingUp, Shield as ShieldCheck, Clock } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "@/contexts/AuthContext";

const Index = () => {
  const { logout } = useAuth();
  
  const [alerts, setAlerts] = useState([
    {
      id: 1,
      title: "Potential Phishing Attack",
      description: "Detected suspicious email activity targeting multiple users.",
      severity: "High",
      status: "Open",
      time: "2 minutes ago"
    },
    {
      id: 2,
      title: "Unusual Network Traffic",
      description: "Observed a spike in outbound traffic from server X.",
      severity: "Medium",
      status: "Investigating",
      time: "15 minutes ago"
    },
    {
      id: 3,
      title: "Unauthorized Access Attempt",
      description: "Failed login attempts detected from an unknown IP address.",
      severity: "Low",
      status: "Resolved",
      time: "1 hour ago"
    },
  ]);

  const [attackPatterns, setAttackPatterns] = useState([
    {
      id: 1,
      type: "SQL Injection",
      source: "185.220.101.33",
      target: "web-server-01",
      severity: "Critical",
      blocked: true,
      time: "3 minutes ago"
    },
    {
      id: 2,
      type: "DDoS Attack",
      source: "Multiple IPs",
      target: "load-balancer",
      severity: "High",
      blocked: true,
      time: "8 minutes ago"
    },
    {
      id: 3,
      type: "Port Scanning",
      source: "203.0.113.45",
      target: "database-server",
      severity: "Medium",
      blocked: false,
      time: "12 minutes ago"
    }
  ]);

  const handleLogout = () => {
    logout();
    toast.success("Logged out successfully");
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical": return "bg-red-500";
      case "High": return "bg-orange-500";
      case "Medium": return "bg-yellow-500";
      case "Low": return "bg-blue-500";
      default: return "bg-gray-500";
    }
  };

  return (
    <div className="min-h-screen bg-[#1a1d29] text-white">
      {/* Fixed Header */}
      <header className="fixed top-0 left-0 right-0 bg-[#2d3748] border-b border-gray-700 z-50 shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-purple-400 mr-3" />
              <h1 className="text-2xl font-bold text-white">Pactrus</h1>
            </div>
            
            <nav className="hidden md:flex space-x-8">
              <Link to="/" className="text-purple-400 font-medium border-b-2 border-purple-400 pb-1">
                Dashboard
              </Link>
              <Link to="/rules" className="text-gray-300 hover:text-white transition-colors">
                Security Rules
              </Link>
              <Link to="/alerts" className="text-gray-300 hover:text-white transition-colors">
                Alerts
              </Link>
              <Link to="/ml-suggestions" className="text-gray-300 hover:text-white transition-colors">
                ML Suggestions
              </Link>
              <Link to="/attack-patterns" className="text-gray-300 hover:text-white transition-colors">
                Attack Patterns
              </Link>
            </nav>

            <div className="flex items-center space-x-4">
              <User className="h-5 w-5 text-gray-300" />
              <Button 
                onClick={handleLogout}
                variant="outline"
                size="sm"
                className="flex items-center gap-2 border-gray-600 text-gray-300 hover:bg-gray-700"
              >
                <LogOut className="h-4 w-4" />
                Logout
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="pt-16">
        <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
          {/* Stats Overview */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4 mb-8">
            <Card className="bg-[#2d3748] border-gray-700">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-400">Active Threats</p>
                    <p className="text-3xl font-bold text-red-400">12</p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-red-400" />
                </div>
              </CardContent>
            </Card>

            <Card className="bg-[#2d3748] border-gray-700">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-400">Blocked Attacks</p>
                    <p className="text-3xl font-bold text-green-400">847</p>
                  </div>
                  <ShieldCheck className="h-8 w-8 text-green-400" />
                </div>
              </CardContent>
            </Card>

            <Card className="bg-[#2d3748] border-gray-700">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-400">Security Score</p>
                    <p className="text-3xl font-bold text-blue-400">89%</p>
                  </div>
                  <TrendingUp className="h-8 w-8 text-blue-400" />
                </div>
              </CardContent>
            </Card>

            <Card className="bg-[#2d3748] border-gray-700">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-400">System Status</p>
                    <p className="text-3xl font-bold text-green-400">Online</p>
                  </div>
                  <Activity className="h-8 w-8 text-green-400" />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Dashboard Content */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Recent Alerts */}
            <Card className="bg-[#2d3748] border-gray-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <AlertTriangle className="mr-2 h-5 w-5 text-orange-400" />
                  Recent Alerts
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {alerts.map((alert) => (
                    <div key={alert.id} className="p-4 bg-[#1a1d29] rounded-lg border border-gray-600">
                      <div className="flex justify-between items-start mb-2">
                        <h3 className="text-white font-medium">{alert.title}</h3>
                        <div className="flex items-center space-x-2">
                          <Badge className={`${getSeverityColor(alert.severity)} text-white text-xs`}>
                            {alert.severity}
                          </Badge>
                          <span className="text-xs text-gray-400">{alert.time}</span>
                        </div>
                      </div>
                      <p className="text-gray-400 text-sm mb-2">{alert.description}</p>
                      <Badge variant="outline" className="text-xs border-gray-600 text-gray-300">
                        {alert.status}
                      </Badge>
                    </div>
                  ))}
                </div>
                <div className="mt-4">
                  <Link to="/alerts">
                    <Button variant="outline" className="w-full border-gray-600 text-gray-300 hover:bg-gray-700">
                      View All Alerts
                    </Button>
                  </Link>
                </div>
              </CardContent>
            </Card>

            {/* Recent Attack Patterns */}
            <Card className="bg-[#2d3748] border-gray-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <Shield className="mr-2 h-5 w-5 text-purple-400" />
                  Recent Attack Patterns
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {attackPatterns.map((pattern) => (
                    <div key={pattern.id} className="p-4 bg-[#1a1d29] rounded-lg border border-gray-600">
                      <div className="flex justify-between items-start mb-2">
                        <div>
                          <h3 className="text-white font-medium">{pattern.type}</h3>
                          <p className="text-gray-400 text-sm">
                            {pattern.source} → {pattern.target}
                          </p>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge className={`${getSeverityColor(pattern.severity)} text-white text-xs`}>
                            {pattern.severity}
                          </Badge>
                          <span className="text-xs text-gray-400">{pattern.time}</span>
                        </div>
                      </div>
                      <div className="flex justify-between items-center">
                        <Badge 
                          variant="outline" 
                          className={`text-xs ${pattern.blocked ? 'border-green-600 text-green-400' : 'border-red-600 text-red-400'}`}
                        >
                          {pattern.blocked ? 'Blocked' : 'Allowed'}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="mt-4">
                  <Link to="/attack-patterns">
                    <Button variant="outline" className="w-full border-gray-600 text-gray-300 hover:bg-gray-700">
                      View All Attack Patterns
                    </Button>
                  </Link>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Quick Actions */}
          <Card className="bg-[#2d3748] border-gray-700 mt-6">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <Activity className="mr-2 h-5 w-5 text-blue-400" />
                Quick Actions
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Button className="bg-purple-600 hover:bg-purple-700 text-white">
                  <Activity className="mr-2 h-4 w-4" />
                  Run Security Scan
                </Button>
                <Button variant="outline" className="border-gray-600 text-gray-300 hover:bg-gray-700">
                  <Shield className="mr-2 h-4 w-4" />
                  Update Rules
                </Button>
                <Button variant="outline" className="border-gray-600 text-gray-300 hover:bg-gray-700">
                  <AlertTriangle className="mr-2 h-4 w-4" />
                  Review Alerts
                </Button>
                <Button variant="outline" className="border-gray-600 text-gray-300 hover:bg-gray-700">
                  <TrendingUp className="mr-2 h-4 w-4" />
                  View Reports
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
};

export default Index;
