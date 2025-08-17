const SURICATA_API_BASE = 'http://192.168.100.20:5000/api'; // Suricata server IP

class SuricataAPI {
  async deployRule(ruleData) {
    try {
      // Generate Suricata rule format
      const suricataRule = this.generateSuricataRule(ruleData);
      
      const response = await fetch(`${SURICATA_API_BASE}/rules`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ rule: suricataRule }),
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error deploying rule:', error);
      throw error;
    }
  }
  
  async getRules() {
    try {
      const response = await fetch(`${SURICATA_API_BASE}/rules`);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return await response.json();
    } catch (error) {
      console.error('Error fetching rules:', error);
      throw error;
    }
  }
  
  async deleteRule(ruleText) {
    try {
      const response = await fetch(`${SURICATA_API_BASE}/rules`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ rule: ruleText }),
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error deleting rule:', error);
      throw error;
    }
  }
  
  async runMLAnalysis() {
    try {
      const response = await fetch(`${SURICATA_API_BASE}/ml/analyze`, {
        method: 'POST',
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error running ML analysis:', error);
      throw error;
    }
  }
  
  async getTrafficStats() {
    try {
      const response = await fetch(`${SURICATA_API_BASE}/traffic/stats`);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return await response.json();
    } catch (error) {
      console.error('Error fetching traffic stats:', error);
      throw error;
    }
  }
  
  async getHealth() {
    try {
      const response = await fetch(`${SURICATA_API_BASE}/health`);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return await response.json();
    } catch (error) {
      console.error('Error checking health:', error);
      throw error;
    }
  }
  
  generateSuricataRule(ruleData) {
    const {
      action = 'alert',
      protocol = 'tcp',
      sourceIp = 'any',
      sourcePort = 'any',
      targetIp = 'any',
      targetPort = '80',
      name = 'Custom Rule',
      customOptions = '',
      priority = 'medium'
    } = ruleData;
    
    const priorityNum = this.getPriorityNumber(priority);
    const sid = Date.now(); // Generate unique SID
    
    return `${action} ${protocol} ${sourceIp} ${sourcePort} -> ${targetIp} ${targetPort} (msg:"${name}"; ${customOptions} sid:${sid}; priority:${priorityNum};)`;
  }
  
  getPriorityNumber(priority) {
    switch (priority.toLowerCase()) {
      case 'critical': return '1';
      case 'high': return '2';
      case 'medium': return '3';
      case 'low': return '4';
      default: return '3';
    }
  }
}

export default new SuricataAPI();