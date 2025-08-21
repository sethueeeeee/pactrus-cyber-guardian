import { useState, useEffect } from "react";
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
  Filter, 
  Plus,
  Edit,
  Trash2,
  Activity,
  User,
  Check,
  Loader2
} from "lucide-react";
import RuleGenerator from "@/components/RuleGenerator";
import { useToast } from "@/hooks/use-toast";

interface Rule {
  id: number;
  name: string;
  attackType: string;
  status: string;
  confidence: number;
  created: string;
  priority: string;
  sourceIp?: string;
  sourcePort?: string;
  targetIp?: string;
  targetPort?: string;
  action?: string;
  protocol?: string;
  description?: string;
  customOptions?: string;
  ruleText?: string;
  isDeployed?: boolean;
}

const Rules = () => {
  const { toast } = useToast();
  const [searchTerm, setSearchTerm] = useState("");
  const [filterType, setFilterType] = useState("all");
  const [isRuleGeneratorOpen, setIsRuleGeneratorOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const [selectedRules, setSelectedRules] = useState<number[]>([]);
  const [deployingRules, setDeployingRules] = useState<number[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);

  useEffect(() => {
    loadRules();
    
    const handleStorageChange = () => {
      loadRules();
    };
    
    window.addEventListener('storage', handleStorageChange);
    window.addEventListener('rulesUpdated', handleStorageChange);
    
    return () => {
      window.removeEventListener('storage', handleStorageChange);
      window.removeEventListener('rulesUpdated', handleStorageChange);
    };
  }, []);

  const loadRules = () => {
    // Load from localStorage
    const storedRules = JSON.parse(localStorage.getItem('securityRules') || '[]');
    setRules(storedRules);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "Active": return "bg-green-500";
      case "Inactive": return "bg-gray-500";
      case "Pending": return "bg-yellow-500";
      case "Draft": return "bg-blue-500";
      default: return "bg-gray-500";
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case "Critical": return "bg-red-500";
      case "High": return "bg-orange-500";
      case "Medium": return "bg-yellow-500";
      case "Low": return "bg-gray-500";
      default: return "bg-gray-500";
    }
  };

  const filteredRules = rules.filter(rule => {
    const matchesSearch = rule.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         rule.attackType.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesFilter = filterType === "all" || rule.status.toLowerCase() === filterType;
    return matchesSearch && matchesFilter;
  });

  const handleSelectRule = (ruleId: number) => {
    setSelectedRules(prev => 
      prev.includes(ruleId) 
        ? prev.filter(id => id !== ruleId)
        : [...prev, ruleId]
    );
  };

  const handleSelectAll = () => {
    setSelectedRules(
      selectedRules.length === filteredRules.length 
        ? [] 
        : filteredRules.map(rule => rule.id)
    );
  };

  const handleEditRule = (rule: Rule) => {
    setEditingRule(rule);
    setIsRuleGeneratorOpen(true);
  };

  const handleDeleteRule = (ruleId: number) => {
    const updatedRules = rules.filter(rule => rule.id !== ruleId);
    setRules(updatedRules);
    localStorage.setItem('securityRules', JSON.stringify(updatedRules));
    
    toast({
      title: "Rule Deleted",
      description: "Rule has been removed successfully.",
    });
  };

  const handleSaveRule = (ruleData: any) => {
    loadRules(); // Reload rules from localStorage
    setEditingRule(null);
    setIsRuleGeneratorOpen(false);
  };

  const generateSuricataRule = (rule: Rule) => {
    // If rule already has ruleText, use it
    if (rule.ruleText) {
      return rule.ruleText;
    }
    
    // Otherwise generate it
    const action = rule.action || 'alert';
    const protocol = rule.protocol || 'tcp';
    const srcIp = rule.sourceIp || 'any';
    const srcPort = rule.sourcePort || 'any';
    const dstIp = rule.targetIp || 'any';
    const dstPort = rule.targetPort || 'any';
    const msg = rule.name || 'Custom rule';
    const priority = rule.priority?.toLowerCase() || 'medium';
    
    const priorityMap: { [key: string]: string } = {
      'critical': '1',
      'high': '2',
      'medium': '3',
      'low': '4'
    };
    
    const priorityNum = priorityMap[priority] || '3';
    const sid = Date.now() % 1000000 + 1000000;
    
    let options = `msg:"${msg}"; `;
    if (rule.customOptions) {
      options += `${rule.customOptions} `;
    }
    options += `sid:${sid}; priority:${priorityNum};`;
    
    return `${action} ${protocol} ${srcIp} ${srcPort} -> ${dstIp} ${dstPort} (${options})`;
  };

  const handleDeployRule = async (ruleId: number) => {
    const rule = rules.find(r => r.id === ruleId);
    if (!rule) return;

    setDeployingRules(prev => [...prev, ruleId]);

    try {
      // Generate Suricata rule
      const suricataRule = generateSuricataRule(rule);
      
      // Deploy to Suricata via API
      const response = await fetch('http://192.168.100.20:5000/api/rules', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ rule: suricataRule }),
      });

      if (response.ok) {
        // Update rule status
        const updatedRules = rules.map(r => 
          r.id === ruleId 
            ? { ...r, status: "Active", isDeployed: true }
            : r
        );
        setRules(updatedRules);
        localStorage.setItem('securityRules', JSON.stringify(updatedRules));

        toast({
          title: "Rule Deployed Successfully",
          description: `Rule "${rule.name}" has been deployed to Suricata.`,
        });
      } else {
        const error = await response.json();
        throw new Error(error.error || 'Deployment failed');
      }
    } catch (error: any) {
      console.error('Deployment error:', error);
      toast({
        title: "Deployment Failed",
        description: error.message || "Failed to deploy rule to Suricata. Please check the API connection.",
        variant: "destructive"
      });
    } finally {
      setDeployingRules(prev => prev.filter(id => id !== ruleId));
    }
  };

  const handleCloseGenerator = () => {
    setEditingRule(null);
    setIsRuleGeneratorOpen(false);
  };

  const handleNewRule = () => {
    setEditingRule(null);
    setIsRuleGeneratorOpen(true);
  };

  return (
    <div className="min-h-screen bg-[#1a1d29] text-white">
      <nav className="bg-[#2d3748] border-b border-gray-700 px-6 py-4 fixed top-0 left-0 right-0 z-50">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-8">
            <div className="flex items-center space-x-2">
              <Shield className="h-8 w-8 text-purple-400" />
              <span className="text-xl font-bold text-white">Pactrus</span>
            </div>
            <div className="hidden md:flex space-x-6">
              <Link to="/" className="text-gray-300 hover:text-white">Dashboard</Link>
              <Link to="/rules" className="text-purple-400 hover:text-purple-300 font-medium">Security Rules</Link>
              <Link to="/ml-suggestions" className="text-gray-300 hover:text-white">ML Suggestions</Link>
              <Link to="/alerts" className="text-gray-300 hover:text-white">Alerts</Link>
              <Link to="/attack-patterns" className="text-gray-300 hover:text-white">Attack Patterns</Link>
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
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white">Security Rules</h1>
            <p className="text-gray-400">Manage your Suricata IDS/IPS rules</p>
          </div>
          <Button 
            onClick={handleNewRule}
            className="bg-purple-500 hover:bg-purple-600 text-white"
          >
            <Plus className="mr-2 h-4 w-4" />
            Generate New Rule
          </Button>
        </div>

        <Card className="bg-[#2d3748] border-gray-700">
          <CardContent className="p-4">
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="Search rules by name or attack type..."
                  className="pl-10 bg-[#1a1d29] border-gray-600 text-white"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
              <div className="flex gap-2">
                <select 
                  className="px-3 py-2 bg-[#1a1d29] border border-gray-600 rounded-md text-white"
                  value={filterType}
                  onChange={(e) => setFilterType(e.target.value)}
                >
                  <option value="all">All Status</option>
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                  <option value="pending">Pending</option>
                  <option value="draft">Draft</option>
                </select>
                <Button variant="outline" className="border-gray-600 text-gray-300">
                  <Filter className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {selectedRules.length > 0 && (
          <Card className="bg-[#2d3748] border-gray-700">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <span className="text-white">{selectedRules.length} rules selected</span>
                <div className="flex gap-2">
                  <Button size="sm" className="bg-green-500 hover:bg-green-600">
                    <Activity className="mr-2 h-4 w-4" />
                    Deploy Selected
                  </Button>
                  <Button size="sm" variant="outline" className="border-gray-600 text-gray-300">
                    Deactivate Selected
                  </Button>
                  <Button size="sm" variant="outline" className="border-red-600 text-red-400">
                    <Trash2 className="mr-2 h-4 w-4" />
                    Delete Selected
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        <Card className="bg-[#2d3748] border-gray-700">
          <CardHeader>
            <CardTitle className="text-white">Rules ({filteredRules.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-gray-600">
                    <TableHead className="text-gray-300">
                      <input
                        type="checkbox"
                        checked={selectedRules.length === filteredRules.length && filteredRules.length > 0}
                        onChange={handleSelectAll}
                        className="mr-2"
                      />
                      Rule Name
                    </TableHead>
                    <TableHead className="text-gray-300">Attack Type</TableHead>
                    <TableHead className="text-gray-300">Status</TableHead>
                    <TableHead className="text-gray-300">Confidence</TableHead>
                    <TableHead className="text-gray-300">Priority</TableHead>
                    <TableHead className="text-gray-300">Created</TableHead>
                    <TableHead className="text-gray-300">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredRules.map((rule) => (
                    <TableRow key={rule.id} className="border-gray-600">
                      <TableCell className="text-white">
                        <div className="flex items-center">
                          <input
                            type="checkbox"
                            checked={selectedRules.includes(rule.id)}
                            onChange={() => handleSelectRule(rule.id)}
                            className="mr-3"
                          />
                          <div>
                            {rule.name}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className="bg-blue-500 text-white">{rule.attackType}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={`${getStatusColor(rule.status)} text-white`}>
                          {rule.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-white">{rule.confidence}%</TableCell>
                      <TableCell>
                        <Badge className={`${getPriorityColor(rule.priority)} text-white`}>
                          {rule.priority}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-gray-400">{rule.created}</TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button 
                            size="sm" 
                            variant="outline" 
                            className="border-gray-600 text-gray-300 hover:bg-gray-700"
                            onClick={() => handleEditRule(rule)}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button 
                            size="sm" 
                            variant="outline" 
                            className="border-red-600 text-red-400 hover:bg-red-900"
                            onClick={() => handleDeleteRule(rule.id)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                          {rule.isDeployed ? (
                            <Button 
                              size="sm" 
                              className="bg-gray-500 cursor-not-allowed"
                              disabled
                            >
                              <Check className="mr-1 h-4 w-4" />
                              Deployed
                            </Button>
                          ) : (
                            <Button 
                              size="sm" 
                              className="bg-green-500 hover:bg-green-600"
                              onClick={() => handleDeployRule(rule.id)}
                              disabled={deployingRules.includes(rule.id)}
                            >
                              {deployingRules.includes(rule.id) ? (
                                <>
                                  <Loader2 className="mr-1 h-4 w-4 animate-spin" />
                                  Deploying...
                                </>
                              ) : (
                                'Deploy'
                              )}
                            </Button>
                          )}
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

      <RuleGenerator 
        isOpen={isRuleGeneratorOpen}
        onClose={handleCloseGenerator}
        onSave={handleSaveRule}
        editingRule={editingRule}
      />
    </div>
  );
};

export default Rules;