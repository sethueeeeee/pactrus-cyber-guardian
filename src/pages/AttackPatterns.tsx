
import { useState } from "react";
import { Link } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { 
  Shield, 
  User,
  Search,
  Filter,
  AlertTriangle,
  Clock,
  MapPin,
  Network,
  Activity,
  Eye,
  Ban,
  CheckCircle
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface AttackDetail {
  id: number;
  type: string;
  sourceIp: string;
  sourcePort: string;
  sourceCountry: string;
  targetIp: string;
  targetPort: string;
  targetService: string;
  severity: string;
  timestamp: string;
  duration: string;
  packets: number;
  bytes: number;
  protocol: string;
  status: "active" | "blocked" | "mitigated";
  description: string;
  recommendedAction: string;
  ruleTriggered?: string;
  geolocation: {
    country: string;
    city: string;
    coordinates: string;
  };
  threatIntel: {
    reputation: string;
    knownMalicious: boolean;
    categories: string[];
  };
}

const AttackPatterns = () => {
  const { toast } = useToast();
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  
  const [attacks, setAttacks] = useState<AttackDetail[]>([
    {
      id: 1,
      type: "SQL Injection",
      sourceIp: "203.0.113.45",
      sourcePort: "54321",
      sourceCountry: "Unknown",
      targetIp: "192.168.1.100",
      targetPort: "80",
      targetService: "HTTP Web Server",
      severity: "Critical",
      timestamp: new Date().toLocaleString(),
      duration: "00:02:45",
      packets: 127,
      bytes: 15420,
      protocol: "TCP",
      status: "active",
      description: "Multiple SQL injection attempts detected targeting login endpoint with UNION-based payload",
      recommendedAction: "Deploy SQL injection blocking rule immediately and patch vulnerable application",
      ruleTriggered: "SQL_INJECTION_UNION_SELECT",
      geolocation: {
        country: "Romania",
        city: "Bucharest", 
        coordinates: "44.4268, 26.1025"
      },
      threatIntel: {
        reputation: "Malicious",
        knownMalicious: true,
        categories: ["Web Attack", "SQL Injection", "Automated Tool"]
      }
    },
    {
      id: 2,
      type: "Port Scan",
      sourceIp: "198.51.100.22",
      sourcePort: "Various",
      sourceCountry: "US",
      targetIp: "192.168.1.0/24",
      targetPort: "1-65535",
      targetService: "Network Infrastructure",
      severity: "Medium",
      timestamp: "2024-01-15 14:17:08",
      duration: "00:15:30",
      packets: 2547,
      bytes: 127350,
      protocol: "TCP",
      status: "blocked",
      description: "Comprehensive port scan across entire network subnet targeting common services",
      recommendedAction: "Implement rate limiting and geo-blocking for suspicious source countries",
      ruleTriggered: "PORT_SCAN_DETECTION",
      geolocation: {
        country: "United States",
        city: "Chicago",
        coordinates: "41.8781, -87.6298"
      },
      threatIntel: {
        reputation: "Suspicious",
        knownMalicious: false,
        categories: ["Reconnaissance", "Port Scanning", "Network Probe"]
      }
    },
    {
      id: 3,
      type: "Brute Force SSH",
      sourceIp: "185.220.101.33",
      sourcePort: "45678",
      sourceCountry: "RU",
      targetIp: "192.168.1.50",
      targetPort: "22",
      targetService: "SSH Server",
      severity: "High",
      timestamp: "2024-01-15 13:44:22",
      duration: "00:08:15",
      packets: 890,
      bytes: 42150,
      protocol: "TCP",
      status: "mitigated",
      description: "Dictionary-based SSH brute force attack with 450+ login attempts using common credentials",
      recommendedAction: "Enable fail2ban, implement key-based authentication, change default SSH port",
      ruleTriggered: "SSH_BRUTE_FORCE",
      geolocation: {
        country: "Russia",
        city: "Moscow",
        coordinates: "55.7558, 37.6176"
      },
      threatIntel: {
        reputation: "Highly Malicious",
        knownMalicious: true,
        categories: ["Brute Force", "SSH Attack", "Credential Stuffing"]
      }
    },
    {
      id: 4,
      type: "DDoS Attack",
      sourceIp: "Multiple IPs",
      sourcePort: "Various",
      sourceCountry: "Multiple",
      targetIp: "192.168.1.10",
      targetPort: "80",
      targetService: "Web Server",
      severity: "Critical",
      timestamp: "2024-01-15 12:15:45",
      duration: "00:25:10",
      packets: 125000,
      bytes: 15750000,
      protocol: "TCP/UDP",
      status: "mitigated",
      description: "Volumetric DDoS attack from botnet targeting web infrastructure with 50Mbps peak traffic",
      recommendedAction: "Activate DDoS protection service, implement rate limiting, contact ISP for upstream filtering",
      ruleTriggered: "DDOS_VOLUME_THRESHOLD",
      geolocation: {
        country: "Various",
        city: "Global Botnet",
        coordinates: "Global"
      },
      threatIntel: {
        reputation: "Botnet",
        knownMalicious: true,
        categories: ["DDoS", "Botnet", "Volumetric Attack"]
      }
    }
  ]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical": return "bg-red-500";
      case "High": return "bg-orange-500";
      case "Medium": return "bg-yellow-500";
      case "Low": return "bg-blue-500";
      default: return "bg-gray-500";
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "active": return "bg-red-500";
      case "blocked": return "bg-yellow-500";
      case "mitigated": return "bg-green-500";
      default: return "bg-gray-500";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "active": return AlertTriangle;
      case "blocked": return Ban;
      case "mitigated": return CheckCircle;
      default: return Clock;
    }
  };

  const blockIP = (attackId: number, ip: string) => {
    // Update the attack status to blocked
    setAttacks(prev => prev.map(attack => 
      attack.id === attackId 
        ? { ...attack, status: "blocked" as const }
        : attack
    ));

    toast({
      title: "IP Address Blocked",
      description: `${ip} has been added to the firewall blacklist.`,
    });
  };

  const createRule = (attack: AttackDetail) => {
    const currentTime = new Date();
    const newRule = {
      id: Date.now() + Math.random(), // Ensure unique ID
      name: `Block ${attack.type} from ${attack.sourceIp}`,
      attackType: attack.type,
      status: "Pending",
      confidence: 90,
      created: currentTime.toISOString().split('T')[0],
      priority: attack.severity,
      sourceIp: attack.sourceIp,
      sourcePort: attack.sourcePort,
      targetIp: attack.targetIp,
      targetPort: attack.targetPort,
      action: attack.severity === "Critical" ? "drop" : "alert",
      protocol: attack.protocol.toLowerCase(),
      description: `Auto-generated rule to block ${attack.type} attacks from ${attack.sourceIp}. ${attack.description}`,
      customOptions: `msg:"${attack.type} blocked from ${attack.sourceIp}"; classtype:attempted-admin;`,
      // Include attack pattern specific data
      attackPatternId: attack.id,
      sourceCountry: attack.sourceCountry,
      targetService: attack.targetService,
      severity: attack.severity,
      packets: attack.packets,
      bytes: attack.bytes,
      duration: attack.duration,
      threatIntel: attack.threatIntel,
      geolocation: attack.geolocation,
      recommendedAction: attack.recommendedAction,
      ruleTriggered: attack.ruleTriggered
    };

    // Add to Security Rules
    const existingRules = JSON.parse(localStorage.getItem('securityRules') || '[]');
    const isDuplicate = existingRules.some((rule: any) => 
      rule.attackPatternId === attack.id ||
      (rule.sourceIp === newRule.sourceIp && rule.attackType === newRule.attackType)
    );
    
    if (!isDuplicate) {
      localStorage.setItem('securityRules', JSON.stringify([...existingRules, newRule]));
      window.dispatchEvent(new Event('storage'));
      
      // Update attack status to show a rule was created
      setAttacks(prev => prev.map(att => 
        att.id === attack.id 
          ? { ...att, status: "mitigated" as const }
          : att
      ));
      
      toast({
        title: "Security Rule Created",
        description: `Rule to block ${attack.type} has been added to Security Rules.`,
      });
    } else {
      toast({
        title: "Rule Already Exists",
        description: "A similar rule already exists in Security Rules.",
        variant: "destructive"
      });
    }
  };

  const filteredAttacks = attacks.filter(attack => {
    const matchesSearch = attack.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         attack.sourceIp.includes(searchTerm) ||
                         attack.targetIp.includes(searchTerm);
    const matchesSeverity = severityFilter === "all" || attack.severity.toLowerCase() === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="min-h-screen bg-[#1a1d29] text-white">
      {/* Fixed Navigation Bar */}
      <nav className="bg-[#2d3748] border-b border-gray-700 px-6 py-4 fixed top-0 left-0 right-0 z-50">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-8">
            <div className="flex items-center space-x-2">
              <Shield className="h-8 w-8 text-purple-400" />
              <span className="text-xl font-bold text-white">Pactrus</span>
            </div>
            <div className="hidden md:flex space-x-6">
              <Link to="/" className="text-gray-300 hover:text-white">Dashboard</Link>
              <Link to="/rules" className="text-gray-300 hover:text-white">Security Rules</Link>
              <Link to="/ml-suggestions" className="text-gray-300 hover:text-white">ML Suggestions</Link>
              <Link to="/alerts" className="text-gray-300 hover:text-white">Alerts</Link>
              <Link to="/attack-patterns" className="text-purple-400 hover:text-purple-300 font-medium">Attack Patterns</Link>
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

      <div className="p-6 space-y-6 pt-24">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white">Attack Patterns Analysis</h1>
            <p className="text-gray-400">Detailed network security threat analysis and response</p>
          </div>
        </div>

        {/* Search and Filter */}
        <Card className="bg-[#2d3748] border-gray-700">
          <CardContent className="p-4">
            <div className="flex gap-4">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="Search by attack type, IP address..."
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

        {/* Attack Details */}
        <div className="space-y-4">
          {filteredAttacks.map((attack) => {
            const StatusIcon = getStatusIcon(attack.status);
            return (
              <Card key={attack.id} className="bg-[#2d3748] border-gray-700">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <StatusIcon className="h-6 w-6 text-red-400" />
                      <CardTitle className="text-white text-xl">{attack.type}</CardTitle>
                      <Badge className={`${getSeverityColor(attack.severity)} text-white`}>
                        {attack.severity}
                      </Badge>
                      <Badge className={`${getStatusColor(attack.status)} text-white`}>
                        {attack.status.toUpperCase()}
                      </Badge>
                    </div>
                    <div className="text-sm text-gray-400">
                      {attack.timestamp}
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-6">
                  <p className="text-gray-300">{attack.description}</p>
                  
                  {/* Network Details */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="space-y-4">
                      <h3 className="text-lg font-semibold text-white flex items-center">
                        <Network className="mr-2 h-5 w-5" />
                        Network Information
                      </h3>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <span className="text-sm text-gray-500">Source IP:</span>
                          <div className="text-white font-mono">{attack.sourceIp}:{attack.sourcePort}</div>
                        </div>
                        <div>
                          <span className="text-sm text-gray-500">Target IP:</span>
                          <div className="text-white font-mono">{attack.targetIp}:{attack.targetPort}</div>
                        </div>
                        <div>
                          <span className="text-sm text-gray-500">Protocol:</span>
                          <div className="text-white">{attack.protocol}</div>
                        </div>
                        <div>
                          <span className="text-sm text-gray-500">Service:</span>
                          <div className="text-white">{attack.targetService}</div>
                        </div>
                        <div>
                          <span className="text-sm text-gray-500">Duration:</span>
                          <div className="text-white">{attack.duration}</div>
                        </div>
                        <div>
                          <span className="text-sm text-gray-500">Traffic:</span>
                          <div className="text-white">{attack.packets} packets / {(attack.bytes / 1024).toFixed(1)} KB</div>
                        </div>
                      </div>
                    </div>

                    <div className="space-y-4">
                      <h3 className="text-lg font-semibold text-white flex items-center">
                        <MapPin className="mr-2 h-5 w-5" />
                        Threat Intelligence
                      </h3>
                      <div className="space-y-3">
                        <div>
                          <span className="text-sm text-gray-500">Location:</span>
                          <div className="text-white">{attack.geolocation.city}, {attack.geolocation.country}</div>
                        </div>
                        <div>
                          <span className="text-sm text-gray-500">Reputation:</span>
                          <Badge className={attack.threatIntel.knownMalicious ? "bg-red-500" : "bg-yellow-500"}>
                            {attack.threatIntel.reputation}
                          </Badge>
                        </div>
                        <div>
                          <span className="text-sm text-gray-500">Categories:</span>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {attack.threatIntel.categories.map((category, index) => (
                              <Badge key={index} variant="outline" className="text-gray-300 border-gray-600">
                                {category}
                              </Badge>
                            ))}
                          </div>
                        </div>
                        {attack.ruleTriggered && (
                          <div>
                            <span className="text-sm text-gray-500">Rule Triggered:</span>
                            <div className="text-white font-mono text-sm">{attack.ruleTriggered}</div>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Recommended Actions */}
                  <div className="p-4 bg-[#1a1d29] rounded-lg border border-gray-600">
                    <h4 className="font-semibold text-white mb-2">Recommended Actions:</h4>
                    <p className="text-gray-300 mb-4">{attack.recommendedAction}</p>
                    <div className="flex gap-2">
                      <Button 
                        size="sm"
                        className="bg-red-500 hover:bg-red-600"
                        onClick={() => blockIP(attack.id, attack.sourceIp)}
                        disabled={attack.status === "blocked"}
                      >
                        <Ban className="mr-2 h-4 w-4" />
                        {attack.status === "blocked" ? "IP Blocked" : "Block IP"}
                      </Button>
                      <Button 
                        size="sm"
                        className="bg-purple-500 hover:bg-purple-600"
                        onClick={() => createRule(attack)}
                      >
                        <Activity className="mr-2 h-4 w-4" />
                        Create Rule
                      </Button>
                      <Button 
                        size="sm"
                        variant="outline"
                        className="border-gray-600 text-gray-300"
                      >
                        <Eye className="mr-2 h-4 w-4" />
                        View in Kibana
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default AttackPatterns;
