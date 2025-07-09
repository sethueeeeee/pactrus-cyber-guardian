
import { useState } from "react";
import { Link } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { 
  Shield, 
  User,
  Brain,
  Zap,
  CheckCircle,
  Clock,
  AlertTriangle,
  Network,
  Activity
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface MLRule {
  id: number;
  title: string;
  description: string;
  confidence: number;
  attackType: string;
  suggestedRule: string;
  sourcePattern: string;
  targetPattern: string;
  severity: string;
  status: "pending" | "deployed" | "rejected";
  createdAt: string;
  deployedAt?: string;
}

const MLRuleSuggestions = () => {
  const { toast } = useToast();
  const [mlRules, setMlRules] = useState<MLRule[]>([
    {
      id: 1,
      title: "Block SQL injection patterns",
      description: "Detected repeated SQL injection attempts from multiple sources targeting login endpoints",
      confidence: 95,
      attackType: "SQL Injection",
      suggestedRule: `alert tcp any any -> 192.168.1.0/24 80 (msg:"SQL Injection detected"; content:"union select"; nocase; classtype:web-application-attack; sid:1000001; priority:1;)`,
      sourcePattern: "203.0.113.45, 198.51.100.22",
      targetPattern: "192.168.1.100:80/login",
      severity: "Critical",
      status: "pending",
      createdAt: "2024-01-15 10:30:00"
    },
    {
      id: 2,
      title: "Rate limit SSH connections",
      description: "Unusual SSH connection patterns detected from multiple IPs indicating brute force attempts",
      confidence: 88,
      attackType: "Brute Force",
      suggestedRule: `drop tcp any any -> any 22 (msg:"SSH Brute Force detected"; detection_filter:track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000002; priority:2;)`,
      sourcePattern: "185.220.101.33, 45.132.75.19",
      targetPattern: "192.168.1.50:22",
      severity: "High",
      status: "pending",
      createdAt: "2024-01-15 09:15:00"
    },
    {
      id: 3,
      title: "Block DDoS traffic patterns",
      description: "High volume traffic detected from botnet sources",
      confidence: 92,
      attackType: "DDoS",
      suggestedRule: `drop tcp any any -> any any (msg:"DDoS attack detected"; threshold:type both, track by_src, count 100, seconds 10; classtype:denial-of-service; sid:1000003; priority:1;)`,
      sourcePattern: "Multiple IPs (Botnet)",
      targetPattern: "192.168.1.0/24",
      severity: "Critical",
      status: "deployed",
      createdAt: "2024-01-14 16:45:00",
      deployedAt: "2024-01-14 17:00:00"
    },
    {
      id: 4,
      title: "Detect malware communication",
      description: "Suspicious outbound connections to known C&C servers",
      confidence: 87,
      attackType: "Malware",
      suggestedRule: `alert tcp 192.168.1.0/24 any -> !192.168.1.0/24 any (msg:"Malware C&C communication"; content:"POST"; http_method; classtype:trojan-activity; sid:1000004; priority:2;)`,
      sourcePattern: "192.168.1.0/24",
      targetPattern: "External C&C servers",
      severity: "High",
      status: "pending",
      createdAt: "2024-01-14 14:20:00"
    }
  ]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical": return "bg-red-500";
      case "High": return "bg-orange-500";
      case "Medium": return "bg-yellow-500";
      default: return "bg-gray-500";
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "deployed": return "bg-green-500";
      case "pending": return "bg-yellow-500";
      case "rejected": return "bg-red-500";
      default: return "bg-gray-500";
    }
  };

  const deployRule = async (ruleId: number) => {
    try {
      // Simulate deployment to Suricata/Ubuntu server
      toast({
        title: "Deploying Rule",
        description: "Sending rule to Suricata server...",
      });

      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 2000));

      setMlRules(prev => prev.map(rule => 
        rule.id === ruleId 
          ? { 
              ...rule, 
              status: "deployed" as const,
              deployedAt: new Date().toISOString().replace('T', ' ').substring(0, 19)
            }
          : rule
      ));

      toast({
        title: "Rule Deployed Successfully",
        description: "Rule has been deployed to Suricata server and added to Security Rules.",
      });

      // Add to Security Rules (simulate by updating localStorage or global state)
      const deployedRule = mlRules.find(rule => rule.id === ruleId);
      if (deployedRule) {
        const securityRule = {
          id: Date.now(),
          name: deployedRule.title,
          attackType: deployedRule.attackType,
          status: "Active",
          confidence: deployedRule.confidence,
          created: new Date().toISOString().split('T')[0],
          priority: deployedRule.severity,
          sourceIp: "any",
          sourcePort: "any",
          targetIp: "any", 
          targetPort: "80",
          action: "alert",
          protocol: "tcp",
          description: deployedRule.description,
          customOptions: ""
        };
        
        // Store in localStorage to persist across page refreshes
        const existingRules = JSON.parse(localStorage.getItem('securityRules') || '[]');
        localStorage.setItem('securityRules', JSON.stringify([...existingRules, securityRule]));
      }

    } catch (error) {
      toast({
        title: "Deployment Failed",
        description: "Failed to deploy rule to Suricata server. Please try again.",
        variant: "destructive"
      });
    }
  };

  const rejectRule = (ruleId: number) => {
    setMlRules(prev => prev.map(rule => 
      rule.id === ruleId 
        ? { ...rule, status: "rejected" as const }
        : rule
    ));

    toast({
      title: "Rule Rejected",
      description: "ML rule suggestion has been rejected.",
    });
  };

  const pendingRules = mlRules.filter(rule => rule.status === "pending");
  const deployedRules = mlRules.filter(rule => rule.status === "deployed");
  const rejectedRules = mlRules.filter(rule => rule.status === "rejected");

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
              <Link to="/ml-suggestions" className="text-purple-400 hover:text-purple-300 font-medium">ML Rule Suggestions</Link>
              <Link to="/alerts" className="text-gray-300 hover:text-white">Alerts</Link>
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
          <div className="flex items-center space-x-3">
            <Brain className="h-8 w-8 text-purple-400" />
            <div>
              <h1 className="text-3xl font-bold text-white">ML Rule Suggestions</h1>
              <p className="text-gray-400">AI-powered security rule recommendations</p>
            </div>
          </div>
          <div className="flex gap-4">
            <Card className="bg-[#2d3748] border-gray-700">
              <CardContent className="p-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-yellow-400">{pendingRules.length}</div>
                  <div className="text-sm text-gray-400">Pending</div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-[#2d3748] border-gray-700">
              <CardContent className="p-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-400">{deployedRules.length}</div>
                  <div className="text-sm text-gray-400">Deployed</div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Pending ML Suggestions */}
        <Card className="bg-[#2d3748] border-gray-700">
          <CardHeader>
            <CardTitle className="text-white flex items-center">
              <Clock className="mr-2 h-5 w-5 text-yellow-400" />
              Pending ML Suggestions ({pendingRules.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {pendingRules.map((rule) => (
              <div key={rule.id} className="p-4 bg-[#1a1d29] rounded-lg border border-gray-600">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="font-semibold text-white text-lg">{rule.title}</h3>
                      <Badge className={`${getSeverityColor(rule.severity)} text-white`}>
                        {rule.severity}
                      </Badge>
                      <Badge className="bg-purple-500 text-white">
                        {rule.confidence}% confidence
                      </Badge>
                    </div>
                    <p className="text-gray-400 mb-3">{rule.description}</p>
                    
                    <div className="grid grid-cols-2 gap-4 mb-3">
                      <div>
                        <span className="text-sm text-gray-500">Attack Type:</span>
                        <div className="text-white">{rule.attackType}</div>
                      </div>
                      <div>
                        <span className="text-sm text-gray-500">Created:</span>
                        <div className="text-white">{rule.createdAt}</div>
                      </div>
                      <div>
                        <span className="text-sm text-gray-500">Source Pattern:</span>
                        <div className="text-white">{rule.sourcePattern}</div>
                      </div>
                      <div>
                        <span className="text-sm text-gray-500">Target Pattern:</span>
                        <div className="text-white">{rule.targetPattern}</div>
                      </div>
                    </div>

                    <div className="mb-3">
                      <span className="text-sm text-gray-500">Suggested Rule:</span>
                      <div className="mt-1 p-2 bg-[#0f1419] rounded border border-gray-600">
                        <code className="text-green-400 text-sm">{rule.suggestedRule}</code>
                      </div>
                    </div>

                    <Progress value={rule.confidence} className="mb-3" />
                  </div>
                </div>

                <div className="flex gap-2">
                  <Button 
                    onClick={() => deployRule(rule.id)}
                    className="bg-green-500 hover:bg-green-600 text-white"
                  >
                    <Activity className="mr-2 h-4 w-4" />
                    Deploy to Suricata
                  </Button>
                  <Button 
                    variant="outline"
                    onClick={() => rejectRule(rule.id)}
                    className="border-red-600 text-red-400 hover:bg-red-900"
                  >
                    <AlertTriangle className="mr-2 h-4 w-4" />
                    Reject
                  </Button>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Deployed Rules */}
        {deployedRules.length > 0 && (
          <Card className="bg-[#2d3748] border-gray-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <CheckCircle className="mr-2 h-5 w-5 text-green-400" />
                Deployed ML Rules ({deployedRules.length})
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {deployedRules.map((rule) => (
                <div key={rule.id} className="p-4 bg-[#1a1d29] rounded-lg border border-green-600">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="font-medium text-white">{rule.title}</h3>
                        <Badge className="bg-green-500 text-white">Deployed</Badge>
                        <Badge className={`${getSeverityColor(rule.severity)} text-white`}>
                          {rule.severity}
                        </Badge>
                      </div>
                      <p className="text-gray-400 text-sm mb-2">{rule.description}</p>
                      <div className="text-sm text-gray-500">
                        Deployed: {rule.deployedAt} | Confidence: {rule.confidence}%
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="h-5 w-5 text-green-400" />
                      <span className="text-green-400 text-sm">Active in Suricata</span>
                    </div>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
};

export default MLRuleSuggestions;
