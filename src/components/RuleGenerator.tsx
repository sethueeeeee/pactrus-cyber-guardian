
import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { 
  Dialog, 
  DialogContent, 
  DialogHeader, 
  DialogTitle, 
  DialogTrigger 
} from "@/components/ui/dialog";

interface RuleGeneratorProps {
  isOpen: boolean;
  onClose: () => void;
  onSave?: (ruleData: any) => void;
  editingRule?: any;
}

const RuleGenerator = ({ isOpen, onClose, onSave, editingRule }: RuleGeneratorProps) => {
  const [ruleConfig, setRuleConfig] = useState({
    attackType: "SQL Injection",
    ruleName: "",
    sourceIp: "any",
    sourcePort: "any",
    targetIp: "any",
    targetPort: "80",
    action: "alert",
    protocol: "tcp",
    description: "",
    priority: "medium",
    customOptions: ""
  });

  const [generatedRule, setGeneratedRule] = useState("");

  // Load editing rule data when component mounts or editingRule changes
  useEffect(() => {
    if (editingRule) {
      setRuleConfig({
        attackType: editingRule.attackType || "SQL Injection",
        ruleName: editingRule.name || "",
        sourceIp: editingRule.sourceIp || "any",
        sourcePort: editingRule.sourcePort || "any",
        targetIp: editingRule.targetIp || "any",
        targetPort: editingRule.targetPort || "80",
        action: editingRule.action || "alert",
        protocol: editingRule.protocol || "tcp",
        description: editingRule.description || "",
        priority: editingRule.priority?.toLowerCase() || "medium",
        customOptions: editingRule.customOptions || ""
      });
    } else {
      // Reset form for new rule
      setRuleConfig({
        attackType: "SQL Injection",
        ruleName: "",
        sourceIp: "any",
        sourcePort: "any",
        targetIp: "any",
        targetPort: "80",
        action: "alert",
        protocol: "tcp",
        description: "",
        priority: "medium",
        customOptions: ""
      });
    }
    setGeneratedRule("");
  }, [editingRule, isOpen]);

  const attackTypes = [
    "SQL Injection", "XSS", "Port Scan", "Brute Force", "DDoS", 
    "Malware", "Phishing", "Directory Traversal", "Command Injection"
  ];

  const generateRule = () => {
    const rule = `${ruleConfig.action} ${ruleConfig.protocol} ${ruleConfig.sourceIp} ${ruleConfig.sourcePort} -> ${ruleConfig.targetIp} ${ruleConfig.targetPort} (msg:"${ruleConfig.ruleName || ruleConfig.attackType} detected"; classtype:${ruleConfig.attackType.toLowerCase().replace(' ', '-')}; sid:1000001; priority:${getPriorityNumber(ruleConfig.priority)}; ${ruleConfig.customOptions})`;
    setGeneratedRule(rule);
  };

  const getPriorityNumber = (priority: string) => {
    switch (priority) {
      case "critical": return "1";
      case "high": return "2";
      case "medium": return "3";
      case "low": return "4";
      default: return "3";
    }
  };

  const handleInputChange = (field: string, value: string) => {
    setRuleConfig(prev => ({ ...prev, [field]: value }));
  };

  const handleSave = () => {
    if (onSave) {
      const ruleData = {
        name: ruleConfig.ruleName || `${ruleConfig.attackType} Rule`,
        attackType: ruleConfig.attackType,
        sourceIp: ruleConfig.sourceIp,
        sourcePort: ruleConfig.sourcePort,
        targetIp: ruleConfig.targetIp,
        targetPort: ruleConfig.targetPort,
        action: ruleConfig.action,
        protocol: ruleConfig.protocol,
        description: ruleConfig.description,
        priority: ruleConfig.priority.charAt(0).toUpperCase() + ruleConfig.priority.slice(1),
        customOptions: ruleConfig.customOptions
      };
      onSave(ruleData);
    }
  };

  const handleClose = () => {
    setGeneratedRule("");
    onClose();
  };

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent className="bg-[#2d3748] border-gray-700 text-white max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="text-white text-xl">
            {editingRule ? "Edit Security Rule" : "Suricata Rule Generator"}
          </DialogTitle>
        </DialogHeader>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Configuration Form */}
          <div className="space-y-4">
            <div>
              <Label className="text-gray-300">Attack Type</Label>
              <select 
                className="w-full mt-1 p-2 bg-[#1a1d29] border border-gray-600 rounded-md text-white"
                value={ruleConfig.attackType}
                onChange={(e) => handleInputChange("attackType", e.target.value)}
              >
                {attackTypes.map(type => (
                  <option key={type} value={type}>{type}</option>
                ))}
              </select>
            </div>

            <div>
              <Label className="text-gray-300">Rule Name</Label>
              <Input 
                className="bg-[#1a1d29] border-gray-600 text-white"
                placeholder="Enter rule name"
                value={ruleConfig.ruleName}
                onChange={(e) => handleInputChange("ruleName", e.target.value)}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label className="text-gray-300">Source IP</Label>
                <Input 
                  className="bg-[#1a1d29] border-gray-600 text-white"
                  placeholder="any or IP address"
                  value={ruleConfig.sourceIp}
                  onChange={(e) => handleInputChange("sourceIp", e.target.value)}
                />
              </div>
              <div>
                <Label className="text-gray-300">Source Port</Label>
                <Input 
                  className="bg-[#1a1d29] border-gray-600 text-white"
                  placeholder="any or port number"
                  value={ruleConfig.sourcePort}
                  onChange={(e) => handleInputChange("sourcePort", e.target.value)}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label className="text-gray-300">Target IP</Label>
                <Input 
                  className="bg-[#1a1d29] border-gray-600 text-white"
                  placeholder="any or IP address"
                  value={ruleConfig.targetIp}
                  onChange={(e) => handleInputChange("targetIp", e.target.value)}
                />
              </div>
              <div>
                <Label className="text-gray-300">Target Port</Label>
                <Input 
                  className="bg-[#1a1d29] border-gray-600 text-white"
                  placeholder="80, 443, etc."
                  value={ruleConfig.targetPort}
                  onChange={(e) => handleInputChange("targetPort", e.target.value)}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label className="text-gray-300">Action</Label>
                <select 
                  className="w-full mt-1 p-2 bg-[#1a1d29] border border-gray-600 rounded-md text-white"
                  value={ruleConfig.action}
                  onChange={(e) => handleInputChange("action", e.target.value)}
                >
                  <option value="alert">Alert</option>
                  <option value="drop">Drop</option>
                  <option value="reject">Reject</option>
                </select>
              </div>
              <div>
                <Label className="text-gray-300">Protocol</Label>
                <select 
                  className="w-full mt-1 p-2 bg-[#1a1d29] border border-gray-600 rounded-md text-white"
                  value={ruleConfig.protocol}
                  onChange={(e) => handleInputChange("protocol", e.target.value)}
                >
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="http">HTTP</option>
                  <option value="https">HTTPS</option>
                </select>
              </div>
            </div>

            <div>
              <Label className="text-gray-300">Priority</Label>
              <select 
                className="w-full mt-1 p-2 bg-[#1a1d29] border border-gray-600 rounded-md text-white"
                value={ruleConfig.priority}
                onChange={(e) => handleInputChange("priority", e.target.value)}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>

            <div>
              <Label className="text-gray-300">Description</Label>
              <Textarea 
                className="bg-[#1a1d29] border-gray-600 text-white"
                placeholder="Describe what this rule detects"
                value={ruleConfig.description}
                onChange={(e) => handleInputChange("description", e.target.value)}
              />
            </div>

            <div>
              <Label className="text-gray-300">Custom Options</Label>
              <Textarea 
                className="bg-[#1a1d29] border-gray-600 text-white"
                placeholder="Additional Suricata rule options"
                value={ruleConfig.customOptions}
                onChange={(e) => handleInputChange("customOptions", e.target.value)}
              />
            </div>
          </div>

          {/* Generated Rule Preview */}
          <div className="space-y-4">
            <div>
              <Label className="text-gray-300">Generated Rule Preview</Label>
              <div className="mt-2 p-4 bg-[#1a1d29] border border-gray-600 rounded-md">
                <code className="text-green-400 text-sm whitespace-pre-wrap">
                  {generatedRule || "Click 'Generate Rule' to preview"}
                </code>
              </div>
            </div>

            <div className="space-y-3">
              <Button 
                onClick={generateRule}
                className="w-full bg-purple-500 hover:bg-purple-600 text-white"
              >
                Generate Rule
              </Button>
              
              {generatedRule && (
                <>
                  <Button 
                    onClick={handleSave}
                    className="w-full bg-green-500 hover:bg-green-600 text-white"
                  >
                    {editingRule ? "Update Rule" : "Save Rule"}
                  </Button>
                  <Button 
                    variant="outline"
                    className="w-full border-gray-600 text-gray-300 hover:bg-gray-700"
                  >
                    Save as Draft
                  </Button>
                </>
              )}
            </div>

            {/* Rule Information */}
            <Card className="bg-[#1a1d29] border-gray-600">
              <CardHeader>
                <CardTitle className="text-sm text-gray-300">Rule Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-gray-400">Attack Type:</span>
                  <Badge className="bg-blue-500">{ruleConfig.attackType}</Badge>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Priority:</span>
                  <Badge className={`${getPriorityColor(ruleConfig.priority)}`}>
                    {ruleConfig.priority.toUpperCase()}
                  </Badge>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Protocol:</span>
                  <span className="text-white">{ruleConfig.protocol.toUpperCase()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Action:</span>
                  <span className="text-white">{ruleConfig.action.toUpperCase()}</span>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};

const getPriorityColor = (priority: string) => {
  switch (priority) {
    case "critical": return "bg-red-500";
    case "high": return "bg-orange-500";
    case "medium": return "bg-yellow-500";
    case "low": return "bg-gray-500";
    default: return "bg-gray-500";
  }
};

export default RuleGenerator;
