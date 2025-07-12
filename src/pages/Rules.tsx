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
  User
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
  // ML Rule specific fields
  mlRuleId?: number;
  suggestedRule?: string;
  sourcePattern?: string;
  targetPattern?: string;
  // Attack Pattern specific fields
  attackPatternId?: number;
  sourceCountry?: string;
  targetService?: string;
  severity?: string;
  packets?: number;
  bytes?: number;
  duration?: string;
  threatIntel?: any;
  geolocation?: any;
  recommendedAction?: string;
  ruleTriggered?: string;
}

const Rules = () => {
  const { toast } = useToast();
  const [searchTerm, setSearchTerm] = useState("");
  const [filterType, setFilterType] = useState("all");
  const [isRuleGeneratorOpen, setIsRuleGeneratorOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const [selectedRules, setSelectedRules] = useState<number[]>([]);

  const [rules, setRules] = useState<Rule[]>([
    {
      id: 1,
      name: "SQL Injection Detection",
      attackType: "SQL Injection",
      status: "Active",
      confidence: 95,
      created: "2024-01-15",
      priority: "Critical",
      sourceIp: "any",
      sourcePort: "any",
      targetIp: "192.168.1.0/24",
      targetPort: "80",
      action: "alert",
      protocol: "tcp",
      description: "Detects SQL injection attempts",
      customOptions: "content:\"union select\"; nocase;"
    },
    {
      id: 2,
      name: "SSH Brute Force Protection",
      attackType: "Brute Force",
      status: "Active",
      confidence: 88,
      created: "2024-01-14",
      priority: "High",
      sourceIp: "any",
      sourcePort: "any",
      targetIp: "any",
      targetPort: "22",
      action: "drop",
      protocol: "tcp",
      description: "Blocks SSH brute force attacks",
      customOptions: "detection_filter:track by_src, count 5, seconds 60;"
    },
    {
      id: 3,
      name: "Port Scan Detection",
      attackType: "Port Scan",
      status: "Inactive",
      confidence: 92,
      created: "2024-01-13",
      priority: "Medium",
      sourceIp: "any",
      sourcePort: "any",
      targetIp: "any",
      targetPort: "any",
      action: "alert",
      protocol: "tcp",
      description: "Detects port scanning activities",
      customOptions: "threshold:type threshold, track by_src, count 10, seconds 60;"
    },
    {
      id: 4,
      name: "XSS Attack Prevention",
      attackType: "XSS",
      status: "Active",
      confidence: 90,
      created: "2024-01-12",
      priority: "High",
      sourceIp: "any",
      sourcePort: "any",
      targetIp: "any",
      targetPort: "80",
      action: "alert",
      protocol: "http",
      description: "Prevents XSS attacks",
      customOptions: "content:\"<script\"; nocase;"
    },
    {
      id: 5,
      name: "DDoS Traffic Filter",
      attackType: "DDoS",
      status: "Pending",
      confidence: 85,
      created: "2024-01-11",
      priority: "Critical",
      sourceIp: "any",
      sourcePort: "any",
      targetIp: "any",
      targetPort: "any",
      action: "drop",
      protocol: "tcp",
      description: "Filters DDoS traffic patterns",
      customOptions: "threshold:type both, track by_src, count 100, seconds 10;"
    }
  ]);

  // Load ML rules and Attack Pattern rules from localStorage on component mount
  useEffect(() => {
    const loadStoredRules = () => {
      const storedRules = JSON.parse(localStorage.getItem('securityRules') || '[]');
      if (storedRules.length > 0) {
        setRules(prev => {
          const existingIds = prev.map(rule => rule.id);
          const newStoredRules = storedRules.filter((storedRule: Rule) => !existingIds.includes(storedRule.id));
          return [...prev, ...newStoredRules];
        });
      }
    };

    loadStoredRules();
    
    // Listen for storage changes to update rules when new rules are added
    const handleStorageChange = () => {
      loadStoredRules();
    };
    
    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case "Active": return "bg-green-500";
      case "Inactive": return "bg-gray-500";
      case "Pending": return "bg-yellow-500";
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
    console.log('Editing rule:', rule); // Debug log
    setEditingRule(rule);
    setIsRuleGeneratorOpen(true);
  };

  const handleDeleteRule = (ruleId: number) => {
    // Remove from local state
    setRules(prev => prev.filter(rule => rule.id !== ruleId));
    
    // Remove from localStorage if it exists there
    const storedRules = JSON.parse(localStorage.getItem('securityRules') || '[]');
    const updatedStoredRules = storedRules.filter((rule: Rule) => rule.id !== ruleId);
    localStorage.setItem('securityRules', JSON.stringify(updatedStoredRules));
    window.dispatchEvent(new Event('storage'));
  };

  const handleSaveRule = (ruleData: any) => {
    if (editingRule) {
      // Update existing rule
      const updatedRule = {
        ...editingRule,
        ...ruleData,
        id: editingRule.id // Keep the original ID
      };
      
      setRules(prev => prev.map(rule => 
        rule.id === editingRule.id ? updatedRule : rule
      ));
      
      // Update in localStorage if it exists there
      const storedRules = JSON.parse(localStorage.getItem('securityRules') || '[]');
      const updatedStoredRules = storedRules.map((rule: Rule) => 
        rule.id === editingRule.id ? updatedRule : rule
      );
      localStorage.setItem('securityRules', JSON.stringify(updatedStoredRules));
      window.dispatchEvent(new Event('storage'));
      
    } else {
      // Add new rule
      const newRule: Rule = {
        id: Date.now() + Math.random(),
        ...ruleData,
        status: "Pending",
        confidence: 95,
        created: new Date().toISOString().split('T')[0]
      };
      setRules(prev => [...prev, newRule]);
    }
    
    setEditingRule(null);
    setIsRuleGeneratorOpen(false);
  };

  const handleDeployRule = async (ruleId: number) => {
    try {
      toast({
        title: "Deploying to Suricata",
        description: "Sending rule to Ubuntu Suricata server in VMware...",
      });

      // Simulate deployment to Suricata/Ubuntu server
      await new Promise(resolve => setTimeout(resolve, 2000));

      setRules(prev => prev.map(rule => 
        rule.id === ruleId 
          ? { ...rule, status: "Active" }
          : rule
      ));

      // Update in localStorage if it exists there
      const storedRules = JSON.parse(localStorage.getItem('securityRules') || '[]');
      const updatedStoredRules = storedRules.map((rule: Rule) => 
        rule.id === ruleId ? { ...rule, status: "Active" } : rule
      );
      localStorage.setItem('securityRules', JSON.stringify(updatedStoredRules));
      window.dispatchEvent(new Event('storage'));

      toast({
        title: "Rule Deployed Successfully",
        description: "Rule has been deployed to Suricata server in VMware.",
      });

    } catch (error) {
      toast({
        title: "Deployment Failed",
        description: "Failed to deploy rule to Suricata server. Please try again.",
        variant: "destructive"
      });
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
        {/* Header */}
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

        {/* Search and Filter Bar */}
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
                </select>
                <Button variant="outline" className="border-gray-600 text-gray-300">
                  <Filter className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Bulk Actions */}
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

        {/* Rules Table */}
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
                            {rule.mlRuleId && <Badge className="ml-2 bg-purple-500 text-xs">ML</Badge>}
                            {rule.attackPatternId && <Badge className="ml-2 bg-blue-500 text-xs">AP</Badge>}
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
                          <Button 
                            size="sm" 
                            className="bg-green-500 hover:bg-green-600"
                            onClick={() => handleDeployRule(rule.id)}
                          >
                            Deploy
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
