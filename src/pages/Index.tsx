
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

  const handleLogout = () => {
    logout();
    toast.success("Logged out successfully");
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
          {/* Welcome Section */}
          <div className="mb-8">
            <h1 className="text-4xl font-bold text-white mb-2">
              Welcome to Pactrus
            </h1>
            <p className="text-xl text-gray-400">
              Your Cyber Guardian Security Platform
            </p>
          </div>

          {/* Stats Overview */}
          <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4 mb-8">
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

          {/* Quick Actions */}
          <Card className="bg-[#2d3748] border-gray-700 mb-8">
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

          {/* Features Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <Card className="bg-[#2d3748] border-gray-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <Shield className="mr-2 h-5 w-5 text-purple-400" />
                  Security Rules
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-gray-400 mb-4">
                  Configure and manage your security rules to protect against various threats.
                </p>
                <Link to="/rules">
                  <Button variant="outline" className="w-full border-gray-600 text-gray-300 hover:bg-gray-700">
                    Manage Rules
                  </Button>
                </Link>
              </CardContent>
            </Card>

            <Card className="bg-[#2d3748] border-gray-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <AlertTriangle className="mr-2 h-5 w-5 text-orange-400" />
                  Security Alerts
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-gray-400 mb-4">
                  Monitor and respond to security alerts in real-time.
                </p>
                <Link to="/alerts">
                  <Button variant="outline" className="w-full border-gray-600 text-gray-300 hover:bg-gray-700">
                    View Alerts
                  </Button>
                </Link>
              </CardContent>
            </Card>

            <Card className="bg-[#2d3748] border-gray-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <TrendingUp className="mr-2 h-5 w-5 text-blue-400" />
                  ML Suggestions
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-gray-400 mb-4">
                  Get AI-powered suggestions for improving your security posture.
                </p>
                <Link to="/ml-suggestions">
                  <Button variant="outline" className="w-full border-gray-600 text-gray-300 hover:bg-gray-700">
                    View Suggestions
                  </Button>
                </Link>
              </CardContent>
            </Card>

            <Card className="bg-[#2d3748] border-gray-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <Activity className="mr-2 h-5 w-5 text-green-400" />
                  Attack Patterns
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-gray-400 mb-4">
                  Analyze attack patterns and behaviors to strengthen defenses.
                </p>
                <Link to="/attack-patterns">
                  <Button variant="outline" className="w-full border-gray-600 text-gray-300 hover:bg-gray-700">
                    Analyze Patterns
                  </Button>
                </Link>
              </CardContent>
            </Card>

            <Card className="bg-[#2d3748] border-gray-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <Clock className="mr-2 h-5 w-5 text-yellow-400" />
                  Real-time Monitoring
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-gray-400 mb-4">
                  Monitor your systems in real-time for immediate threat detection.
                </p>
                <Button variant="outline" className="w-full border-gray-600 text-gray-300 hover:bg-gray-700">
                  Start Monitoring
                </Button>
              </CardContent>
            </Card>

            <Card className="bg-[#2d3748] border-gray-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <ShieldCheck className="mr-2 h-5 w-5 text-cyan-400" />
                  Compliance Reports
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-gray-400 mb-4">
                  Generate comprehensive compliance and security reports.
                </p>
                <Button variant="outline" className="w-full border-gray-600 text-gray-300 hover:bg-gray-700">
                  Generate Reports
                </Button>
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Index;
