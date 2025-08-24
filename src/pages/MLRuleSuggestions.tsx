import { useState, useEffect } from "react";
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
  Activity,
  RefreshCw,
  Loader2
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
  sourceIp?: string;
  targetIp?: string;
  attack_count?: number;
  attack_rate?: number;
}

const MLRuleSuggestions = () => {
  const { toast } = useToast();
  const [mlRules, setMlRules] = useState<MLRule[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string>("");
  const SURICATA_API = "http://192.168.100.20:5000/api";

  // Fetch real ML suggestions from backend
  const fetchMLSuggestions = async () => {
    try {
      setIsRefreshing(true);
      const response = await fetch(`${SURICATA_API}/ml/suggestions/live`);
      
      if (!response.ok) {
        throw new Error('Failed to fetch ML suggestions');
      }
      
      const data = await response.json();
      
      if (data.ok && data.suggestions) {
        setMlRules(data.suggestions);
        setLastUpdated(new Date().toLocaleString());
        
        // Store in localStorage for offline access
        localStorage.setItem('mlRules', JSON.stringify(data.suggestions));
        
        toast({
          title: "ML Suggestions Updated",
          description: `Loaded ${data.suggestions.length} suggestions from ML analyzer`,
        });
      }
    } catch (error) {
      console.error('Error fetching ML suggestions:', error);
      
      // Try to load from localStorage as fallback
      const cached = localStorage.getItem('mlRules');
      if (cached) {
        setMlRules(JSON.parse(cached));
        toast({
          title: "Using Cached Data",
          description: "Could not connect to ML analyzer. Showing cached suggestions.",
          variant: "destructive"
        });
      } else {
        toast({
          title: "Connection Error",
          description: "Could not fetch ML suggestions. Check if the API server is running.",
          variant: "destructive"
        });
      }
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  // Trigger ML analysis
  const triggerMLAnalysis = async () => {
    try {
      setIsRefreshing(true);
      toast({
        title: "Running ML Analysis",
        description: "Analyzing recent attack patterns...",
      });

      const response = await fetch(`${SURICATA_API}/ml/analyze`, {
        method: 'POST'
      });

      if (response.ok) {
        const data = await response.json();
        
        toast({
          title: "Analysis Complete",
          description: `Generated ${data.suggestions?.length || 0} new suggestions`,
        });
        
        // Refresh suggestions after analysis
        await fetchMLSuggestions();
      } else {
        throw new Error('Analysis failed');
      }
    } catch (error) {
      toast({
        title: "Analysis Error",
        description: "Failed to run ML analysis. Check server connection.",
        variant: "destructive"
      });
    } finally {
      setIsRefreshing(false);
    }
  };

  // Deploy rule to Suricata
  const deployRule = async (ruleId: number) => {
    try {
      const rule = mlRules.find(r => r.id === ruleId);
      if (!rule) return;

      toast({
        title: "Deploying Rule",
        description: "Sending rule to Suricata server...",
      });

      const response = await fetch(`${SURICATA_API}/ml/suggestions/deploy`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ id: ruleId })
      });

      if (response.ok) {
        // Update local state
        setMlRules(prev => prev.map(r => 
          r.id === ruleId 
            ? { ...r, status: "deployed" as const, deployedAt: new Date().toISOString() }
            : r
        ));

        // Also save to Security Rules
        const securityRule = {
          id: Date.now() + Math.random(),
          name: rule.title,
          attackType: rule.attackType,
          status: "Active",
          confidence: rule.confidence,
          created: new Date().toISOString().split('T')[0],
          priority: rule.severity,
          sourceIp: rule.sourceIp || "any",
          targetIp: rule.targetIp || "any",
          description: rule.description,
          suggestedRule: rule.suggestedRule,
          mlRuleId: rule.id
        };

        const existingRules = JSON.parse(localStorage.getItem('securityRules') || '[]');
        localStorage.setItem('securityRules', JSON.stringify([...existingRules, securityRule]));
        window.dispatchEvent(new Event('storage'));

        toast({
          title: "Rule Deployed Successfully",
          description: "Rule has been deployed to Suricata and added to Security Rules.",
        });
      } else {
        throw new Error('Deployment failed');
      }
    } catch (error) {
      toast({
        title: "Deployment Failed",
        description: "Failed to deploy rule. Check server connection.",
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

  // Train ML model manually
  const triggerTraining = async () => {
    try {
      setIsRefreshing(true);
      toast({
        title: "Training ML Model",
        description: "This may take a few moments...",
      });

      const response = await fetch(`${SURICATA_API}/ml/train`, {
        method: 'POST'
      });

      const data = await response.json();

      if (data.success) {
        toast({
          title: "Training Complete",
          description: `Model trained with ${data.samples} samples`,
        });
        
        // Refresh suggestions after training
        await fetchMLSuggestions();
      } else {
        throw new Error(data.message || 'Training failed');
      }
    } catch (error: any) {
      toast({
        title: "Training Failed",
        description: error.message || "Failed to train ML model",
        variant: "destructive"
      });
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchMLSuggestions();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchMLSuggestions, 30000);
    
    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical": return "bg-red-500";
      case "High": return "bg-orange-500";
      case "Medium": return "bg-yellow-500";
      case "Low": return "bg-blue-500";
      default: return "bg-gray-500";
    }
  };

  const pendingRules = mlRules.filter(rule => rule.status === "pending");
  const deployedRules = mlRules.filter(rule => rule.status === "deployed");

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#1a1d29] text-white flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin text-purple-400 mx-auto mb-4" />
          <p>Loading ML suggestions...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#1a1d29] text-white">
      {/* Navigation */}
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
              <Link to="/ml-suggestions" className="text-purple-400 hover:text-purple-300 font-medium">ML Suggestions</Link>
              <Link to="/alerts" className="text-gray-300 hover:text-white">Alerts</Link>
              <Link to="/attack-patterns" className="text-gray-300 hover:text-white">Attack Patterns</Link>
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
          <div className="flex items-center space-x-3">
            <Brain className="h-8 w-8 text-purple-400" />
            <div>
              <h1 className="text-3xl font-bold text-white">ML Rule Suggestions</h1>
              <p className="text-gray-400">Real-time AI-powered security rule recommendations</p>
              {lastUpdated && (
                <p className="text-sm text-gray-500 mt-1">Last updated: {lastUpdated}</p>
              )}
            </div>
          </div>
          <div className="flex gap-4">
            <Button
              onClick={triggerTraining}
              disabled={isRefreshing}
              className="bg-purple-500 hover:bg-purple-600"
            >
              {isRefreshing ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Brain className="mr-2 h-4 w-4" />
              )}
              Train Model
            </Button>
            <Button
              onClick={triggerMLAnalysis}
              disabled={isRefreshing}
              className="bg-blue-500 hover:bg-blue-600"
            >
              {isRefreshing ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Activity className="mr-2 h-4 w-4" />
              )}
              Run Analysis
            </Button>
            <Button
              onClick={fetchMLSuggestions}
              disabled={isRefreshing}
              variant="outline"
              className="border-gray-600"
            >
              <RefreshCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} />
            </Button>
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
            {pendingRules.length === 0 ? (
              <div className="text-center py-8 text-gray-400">
                <Brain className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No pending ML suggestions at the moment.</p>
                <p className="text-sm mt-2">Run an analysis or wait for the next automatic scan.</p>
              </div>
            ) : (
              pendingRules.map((rule) => (
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
                          <div className="text-white">{new Date(rule.createdAt).toLocaleString()}</div>
                        </div>
                        <div>
                          <span className="text-sm text-gray-500">Source Pattern:</span>
                          <div className="text-white font-mono text-sm">{rule.sourcePattern}</div>
                        </div>
                        <div>
                          <span className="text-sm text-gray-500">Target Pattern:</span>
                          <div className="text-white font-mono text-sm">{rule.targetPattern}</div>
                        </div>
                        {rule.attack_count && (
                          <div>
                            <span className="text-sm text-gray-500">Attack Count:</span>
                            <div className="text-white">{rule.attack_count} incidents</div>
                          </div>
                        )}
                        {rule.attack_rate && rule.attack_rate > 0 && (
                          <div>
                            <span className="text-sm text-gray-500">Attack Rate:</span>
                            <div className="text-white">{rule.attack_rate.toFixed(1)} per minute</div>
                          </div>
                        )}
                      </div>

                      <div className="mb-3">
                        <span className="text-sm text-gray-500">Suggested Rule:</span>
                        <div className="mt-1 p-2 bg-[#0f1419] rounded border border-gray-600">
                          <code className="text-green-400 text-xs break-all">{rule.suggestedRule}</code>
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
              ))
            )}
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
                        Deployed: {rule.deployedAt ? new Date(rule.deployedAt).toLocaleString() : 'Unknown'} | 
                        Confidence: {rule.confidence}%
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