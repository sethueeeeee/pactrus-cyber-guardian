import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  Settings, 
  User, 
  TrendingUp,
  Database,
  Zap,
  Monitor,
  Bell
} from "lucide-react";
import RuleGenerator from "@/components/RuleGenerator";

const Index = () => {
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const [isRuleGeneratorOpen, setIsRuleGeneratorOpen] = useState(false);
  const navigate = useNavigate();

  // Sample data for the dashboard
  const stats = {
    generatedRules: { count: 47, change: "+8 today" },
    deployedRules: { count: 42, pending: 5 },
    mlSuggestions: { count: 12, description: "based on recent attacks" },
    activeAlerts: { count: 3, critical: 2 }
  };

  const recentAttacks = [
    {
      type: "SQL Injection",
      sourceIp: "203.0.113.45",
      targetIp: "192.168.1.100",
      severity: "Critical",
      timestamp: "2 min ago",
      mlSuggested: true
    },
    {
      type: "Port Scan",
      sourceIp: "198.51.100.22",
      targetIp: "192.168.1.0/24",
      severity: "Medium",
      timestamp: "15 min ago",
      mlSuggested: false
    },
    {
      type: "Brute Force SSH",
      sourceIp: "185.220.101.33",
      targetIp: "192.168.1.50",
      severity: "High",
      timestamp: "28 min ago",
      mlSuggested: true
    }
  ];

  const mlSuggestions = [
    {
      title: "Block SQL injection patterns",
      confidence: 95,
      description: "Detected repeated SQL injection attempts from multiple sources"
    },
    {
      title: "Rate limit SSH connections",
      confidence: 88,
      description: "Unusual SSH connection patterns detected"
    }
  ];

  const serviceStatus = [
    { name: "Ubuntu Suricata", status: "Connected", color: "bg-green-500" },
    { name: "Elasticsearch", status: "Online", color: "bg-green-500" },
    { name: "Kibana Dashboard", status: "Active", color: "bg-green-500" },
    { name: "Telegram Bot", status: "Ready", color: "bg-green-500" }
  ];

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical": return "bg-red-500";
      case "High": return "bg-orange-500";
      case "Medium": return "bg-yellow-500";
      default: return "bg-gray-500";
    }
  };

  const handleQuickAction = (action: string) => {
    switch (action) {
      case "generate":
        setIsRuleGeneratorOpen(true);
        break;
      case "deploy":
        navigate("/rules");
        break;
      case "monitor":
        window.open("http://kibana.example.com", "_blank");
        break;
      case "alerts":
        navigate("/alerts");
        break;
    }
  };

  const handleMLSuggestionClick = () => {
    navigate("/ml-suggestions");
  };

  const handleAttackPatternClick = () => {
    navigate("/attack-patterns");
  };

  return (
    <div className="min-h-screen bg-[#1a1d29] text-white">
      {/* Navigation Bar */}
      <nav className="bg-[#2d3748] border-b border-gray-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-8">
            <div className="flex items-center space-x-2">
              <Shield className="h-8 w-8 text-purple-400" />
              <span className="text-xl font-bold text-white">CyberGuard</span>
            </div>
            <div className="hidden md:flex space-x-6">
              <Link to="/" className="text-purple-400 hover:text-purple-300 font-medium">Dashboard</Link>
              <Link to="/rules" className="text-gray-300 hover:text-white">Security Rules</Link>
              <Link to="/ml-suggestions" className="text-gray-300 hover:text-white">ML Suggestions</Link>
              <Link to="/alerts" className="text-gray-300 hover:text-white">Alerts</Link>
              <Link to="/attack-patterns" className="text-gray-300 hover:text-white">Attack Patterns</Link>
              <Link to="/monitoring" className="text-gray-300 hover:text-white">Monitoring</Link>
              <Link to="/telegram" className="text-gray-300 hover:text-white">Telegram</Link>
              <Link to="/settings" className="text-gray-300 hover:text-white">Settings</Link>
            </div>
          </div>
          <div className="relative">
            <Button
              variant="ghost"
              className="text-gray-300 hover:text-white"
              onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
            >
              <User className="h-5 w-5" />
            </Button>
            {isUserMenuOpen && (
              <div className="absolute right-0 mt-2 w-48 bg-[#2d3748] border border-gray-600 rounded-md shadow-lg z-10">
                <div className="py-1">
                  <button className="block w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-gray-700">Profile</button>
                  <button className="block w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-gray-700">Settings</button>
                  <hr className="border-gray-600 my-1" />
                  <button className="block w-full text-left px-4 py-2 text-sm text-red-400 hover:bg-gray-700">Logout</button>
                </div>
              </div>
            )}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="p-6 space-y-6">
        {/* Dashboard Statistics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card className="bg-[#2d3748] border-gray-700">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">Generated Rules</CardTitle>
              <Database className="h-4 w-4 text-blue-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{stats.generatedRules.count}</div>
              <p className="text-xs text-green-400">{stats.generatedRules.change}</p>
            </CardContent>
          </Card>

          <Card className="bg-[#2d3748] border-gray-700">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">Deployed Rules</CardTitle>
              <Activity className="h-4 w-4 text-green-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{stats.deployedRules.count}</div>
              <p className="text-xs text-yellow-400">{stats.deployedRules.pending} pending deployment</p>
            </CardContent>
          </Card>

          <Card className="bg-[#2d3748] border-gray-700">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">ML Suggestions</CardTitle>
              <Zap className="h-4 w-4 text-purple-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{stats.mlSuggestions.count}</div>
              <p className="text-xs text-gray-400">{stats.mlSuggestions.description}</p>
            </CardContent>
          </Card>

          <Card className="bg-[#2d3748] border-gray-700">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">Active Alerts</CardTitle>
              <AlertTriangle className="h-4 w-4 text-red-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{stats.activeAlerts.count}</div>
              <p className="text-xs text-red-400">{stats.activeAlerts.critical} critical threats</p>
            </CardContent>
          </Card>
        </div>

        {/* Recent Attack Patterns */}
        <Card className="bg-[#2d3748] border-gray-700">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-white">Recent Attack Patterns</CardTitle>
              <Button 
                variant="outline" 
                size="sm" 
                className="border-purple-400 text-purple-400 hover:bg-purple-400 hover:text-white"
                onClick={handleAttackPatternClick}
              >
                View Detailed Analysis
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentAttacks.map((attack, index) => (
                <div 
                  key={index} 
                  className="flex items-center justify-between p-4 bg-[#1a1d29] rounded-lg border border-gray-600 cursor-pointer hover:border-purple-400 transition-colors"
                  onClick={handleAttackPatternClick}
                >
                  <div className="flex items-center space-x-4">
                    <Badge className={`${getSeverityColor(attack.severity)} text-white`}>
                      {attack.severity}
                    </Badge>
                    <div>
                      <div className="font-medium text-white">{attack.type}</div>
                      <div className="text-sm text-gray-400">
                        {attack.sourceIp} → {attack.targetIp}
                      </div>
                    </div>
                    {attack.mlSuggested && (
                      <Badge className="bg-purple-500 text-white">ML Suggested</Badge>
                    )}
                  </div>
                  <div className="text-sm text-gray-400">{attack.timestamp}</div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* ML Rule Suggestions */}
          <Card className="bg-[#2d3748] border-gray-700">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-white">ML Rule Suggestions</CardTitle>
                <Button 
                  variant="link" 
                  className="text-purple-400 hover:text-purple-300"
                  onClick={handleMLSuggestionClick}
                >
                  View All Suggestions
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {mlSuggestions.map((suggestion, index) => (
                <div key={index} className="p-4 bg-[#1a1d29] rounded-lg border border-gray-600">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="font-medium text-white">{suggestion.title}</h3>
                    <Badge className="bg-purple-500 text-white">{suggestion.confidence}% confidence</Badge>
                  </div>
                  <p className="text-sm text-gray-400 mb-3">{suggestion.description}</p>
                  <div className="flex gap-2">
                    <Button 
                      size="sm" 
                      className="bg-purple-500 hover:bg-purple-600 text-white"
                      onClick={() => setIsRuleGeneratorOpen(true)}
                    >
                      Generate Rule
                    </Button>
                    <Button 
                      size="sm" 
                      variant="outline"
                      className="border-purple-400 text-purple-400 hover:bg-purple-400 hover:text-white"
                      onClick={handleMLSuggestionClick}
                    >
                      View Details
                    </Button>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Suricata Deployment Status */}
          <Card className="bg-[#2d3748] border-gray-700">
            <CardHeader>
              <CardTitle className="text-white">Suricata Deployment Status</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {serviceStatus.map((service, index) => (
                <div key={index} className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className={`w-3 h-3 rounded-full ${service.color}`}></div>
                    <span className="text-white">{service.name}</span>
                  </div>
                  <Badge variant="outline" className="text-green-400 border-green-400">
                    {service.status}
                  </Badge>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Quick Actions */}
        <Card className="bg-[#2d3748] border-gray-700">
          <CardHeader>
            <CardTitle className="text-white">Quick Actions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <Button 
                className="bg-blue-500 hover:bg-blue-600 text-white"
                onClick={() => handleQuickAction("generate")}
              >
                <Database className="mr-2 h-4 w-4" />
                Generate New Rule
              </Button>
              <Button 
                className="bg-green-500 hover:bg-green-600 text-white"
                onClick={() => handleQuickAction("deploy")}
              >
                <Activity className="mr-2 h-4 w-4" />
                Deploy to Suricata
              </Button>
              <Button 
                className="bg-purple-500 hover:bg-purple-600 text-white"
                onClick={() => handleQuickAction("monitor")}
              >
                <Monitor className="mr-2 h-4 w-4" />
                Monitor Traffic
              </Button>
              <Button 
                className="bg-orange-500 hover:bg-orange-600 text-white"
                onClick={() => handleQuickAction("alerts")}
              >
                <Bell className="mr-2 h-4 w-4" />
                Configure Alerts
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      <RuleGenerator 
        isOpen={isRuleGeneratorOpen}
        onClose={() => setIsRuleGeneratorOpen(false)}
      />
    </div>
  );
};

export default Index;
