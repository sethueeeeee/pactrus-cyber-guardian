
import { useState } from "react";
import { Link } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import { 
  Shield, 
  Search, 
  AlertTriangle,
  Clock,
  User,
  ExternalLink,
  Bell
} from "lucide-react";

const Alerts = () => {
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");

  const alerts = [
    {
      id: 1,
      type: "SQL Injection Attack",
      sourceIp: "203.0.113.45",
      targetIp: "192.168.1.100",
      severity: "Critical",
      timestamp: "2024-01-20 14:32:15",
      status: "Active",
      description: "Multiple SQL injection attempts detected from external IP",
      ruleId: "SID-1001"
    },
    {
      id: 2,
      type: "Brute Force SSH",
      sourceIp: "185.220.101.33",
      targetIp: "192.168.1.50",
      severity: "High",
      timestamp: "2024-01-20 14:28:42",
      status: "Investigating",
      description: "Repeated failed SSH login attempts",
      ruleId: "SID-1002"
    },
    {
      id: 3,
      type: "Port Scan",
      sourceIp: "198.51.100.22",
      targetIp: "192.168.1.0/24",
      severity: "Medium",
      timestamp: "2024-01-20 14:15:30",
      status: "Resolved",
      description: "Network port scanning activity detected",
      ruleId: "SID-1003"
    },
    {
      id: 4,
      type: "Malware Communication",
      sourceIp: "192.168.1.75",
      targetIp: "198.51.100.180",
      severity: "Critical",
      timestamp: "2024-01-20 13:45:18",
      status: "Active",
      description: "Suspicious outbound communication to known C&C server",
      ruleId: "SID-1004"
    },
    {
      id: 5,
      type: "DDoS Attack",
      sourceIp: "Multiple IPs",
      targetIp: "192.168.1.10",
      severity: "High",
      timestamp: "2024-01-20 13:22:05",
      status: "Mitigated",
      description: "Distributed denial of service attack detected and blocked",
      ruleId: "SID-1005"
    }
  ];

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical": return "bg-red-500";
      case "High": return "bg-orange-500";
      case "Medium": return "bg-yellow-500";
      case "Low": return "bg-gray-500";
      default: return "bg-gray-500";
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "Active": return "bg-red-500";
      case "Investigating": return "bg-yellow-500";
      case "Resolved": return "bg-green-500";
      case "Mitigated": return "bg-blue-500";
      default: return "bg-gray-500";
    }
  };

  const filteredAlerts = alerts.filter(alert => {
    const matchesSearch = alert.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         alert.sourceIp.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         alert.targetIp.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = severityFilter === "all" || alert.severity.toLowerCase() === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const activeAlertsCount = alerts.filter(alert => alert.status === "Active").length;
  const criticalAlertsCount = alerts.filter(alert => alert.severity === "Critical").length;
  const resolvedTodayCount = alerts.filter(alert => 
    alert.status === "Resolved" && alert.timestamp.includes("2024-01-20")
  ).length;

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
              <Link to="/" className="text-gray-300 hover:text-white">Dashboard</Link>
              <Link to="/rules" className="text-gray-300 hover:text-white">Security Rules</Link>
              <Link to="/alerts" className="text-purple-400 hover:text-purple-300 font-medium">Alerts</Link>
              <Link to="/monitoring" className="text-gray-300 hover:text-white">Monitoring</Link>
              <Link to="/telegram" className="text-gray-300 hover:text-white">Telegram</Link>
              <Link to="/settings" className="text-gray-300 hover:text-white">Settings</Link>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <User className="h-5 w-5 text-gray-300" />
          </div>
        </div>
      </nav>

      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white">Security Alerts</h1>
            <p className="text-gray-400">Monitor and manage security incidents</p>
          </div>
          <div className="flex space-x-2">
            <Button className="bg-purple-500 hover:bg-purple-600 text-white">
              <Bell className="mr-2 h-4 w-4" />
              Configure Alerts
            </Button>
            <Button variant="outline" className="border-gray-600 text-gray-300">
              <ExternalLink className="mr-2 h-4 w-4" />
              View in Kibana
            </Button>
          </div>
        </div>

        {/* Alert Statistics */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <Card className="bg-[#2d3748] border-gray-700">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">Active Alerts</CardTitle>
              <AlertTriangle className="h-4 w-4 text-red-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{activeAlertsCount}</div>
              <p className="text-xs text-red-400">Require immediate attention</p>
            </CardContent>
          </Card>

          <Card className="bg-[#2d3748] border-gray-700">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">Critical Threats</CardTitle>
              <Shield className="h-4 w-4 text-red-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{criticalAlertsCount}</div>
              <p className="text-xs text-red-400">High priority incidents</p>
            </CardContent>
          </Card>

          <Card className="bg-[#2d3748] border-gray-700">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">Resolved Today</CardTitle>
              <Clock className="h-4 w-4 text-green-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{resolvedTodayCount}</div>
              <p className="text-xs text-green-400">Successfully handled</p>
            </CardContent>
          </Card>

          <Card className="bg-[#2d3748] border-gray-700">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">Total Alerts</CardTitle>
              <Bell className="h-4 w-4 text-blue-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{alerts.length}</div>
              <p className="text-xs text-blue-400">Last 24 hours</p>
            </CardContent>
          </Card>
        </div>

        {/* Search and Filter */}
        <Card className="bg-[#2d3748] border-gray-700">
          <CardContent className="p-4">
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="Search alerts by type, IP address, or description..."
                  className="pl-10 bg-[#1a1d29] border-gray-600 text-white"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
              <select 
                className="px-3 py-2 bg-[#1a1d29] border border-gray-600 rounded-md text-white"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </CardContent>
        </Card>

        {/* Alerts Table */}
        <Card className="bg-[#2d3748] border-gray-700">
          <CardHeader>
            <CardTitle className="text-white">Recent Alerts ({filteredAlerts.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-gray-600">
                    <TableHead className="text-gray-300">Alert Type</TableHead>
                    <TableHead className="text-gray-300">Source → Target</TableHead>
                    <TableHead className="text-gray-300">Severity</TableHead>
                    <TableHead className="text-gray-300">Status</TableHead>
                    <TableHead className="text-gray-300">Timestamp</TableHead>
                    <TableHead className="text-gray-300">Rule ID</TableHead>
                    <TableHead className="text-gray-300">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredAlerts.map((alert) => (
                    <TableRow key={alert.id} className="border-gray-600">
                      <TableCell>
                        <div>
                          <div className="font-medium text-white">{alert.type}</div>
                          <div className="text-sm text-gray-400">{alert.description}</div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="text-white">
                          <div>{alert.sourceIp}</div>
                          <div className="text-gray-400">↓</div>
                          <div>{alert.targetIp}</div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={`${getSeverityColor(alert.severity)} text-white`}>
                          {alert.severity}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={`${getStatusColor(alert.status)} text-white`}>
                          {alert.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-gray-400">{alert.timestamp}</TableCell>
                      <TableCell className="text-blue-400">{alert.ruleId}</TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button size="sm" variant="outline" className="border-blue-600 text-blue-400">
                            Investigate
                          </Button>
                          <Button size="sm" variant="outline" className="border-green-600 text-green-400">
                            Resolve
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Alerts;
