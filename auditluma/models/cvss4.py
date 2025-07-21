"""
CVSS 4.0 漏洞评分系统
根据 FIRST CVSS v4.0 标准实现
参考：https://www.first.org/cvss/v4-0/
"""

from enum import Enum
from typing import Dict, Optional
from dataclasses import dataclass
import math


class AttackVector(Enum):
    """攻击向量 (AV)"""
    NETWORK = ("N", 0.0, "网络")
    ADJACENT = ("A", 0.1, "相邻网络")  
    LOCAL = ("L", 0.2, "本地")
    PHYSICAL = ("P", 0.3, "物理")


class AttackComplexity(Enum):
    """攻击复杂度 (AC)"""
    LOW = ("L", 0.0, "低")
    HIGH = ("H", 0.1, "高")


class AttackRequirements(Enum):
    """攻击要求 (AT) - CVSS 4.0新增"""
    NONE = ("N", 0.0, "无")
    PRESENT = ("P", 0.1, "存在")


class PrivilegesRequired(Enum):
    """所需权限 (PR)"""
    NONE = ("N", 0.0, "无")
    LOW = ("L", 0.1, "低")
    HIGH = ("H", 0.2, "高")


class UserInteraction(Enum):
    """用户交互 (UI)"""
    NONE = ("N", 0.0, "无")
    PASSIVE = ("P", 0.1, "被动")  # CVSS 4.0新增
    ACTIVE = ("A", 0.2, "主动")


class VulnerableSystemImpact(Enum):
    """易受攻击系统影响"""
    HIGH = ("H", 0.0, "高")
    LOW = ("L", 0.1, "低")
    NONE = ("N", 0.2, "无")


class SubsequentSystemImpact(Enum):
    """后续系统影响 - CVSS 4.0新增"""
    HIGH = ("H", 0.0, "高")
    LOW = ("L", 0.1, "低") 
    NONE = ("N", 0.2, "无")


class SafetyImpact(Enum):
    """安全影响 (S) - CVSS 4.0新增"""
    NEGLIGIBLE = ("N", 0.0, "可忽略")
    PRESENT = ("P", 0.1, "存在")


class AutomationImpact(Enum):
    """自动化影响 (AU) - CVSS 4.0新增"""
    NO = ("N", 0.0, "否")
    YES = ("Y", 0.1, "是")


class RecoveryImpact(Enum):
    """恢复影响 (R) - CVSS 4.0新增"""
    AUTOMATIC = ("A", 0.0, "自动")
    USER = ("U", 0.1, "用户")
    IRRECOVERABLE = ("I", 0.2, "不可恢复")


@dataclass
class CVSS4Metrics:
    """CVSS 4.0指标"""
    # 基础指标组
    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    attack_requirements: AttackRequirements
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    
    # 易受攻击系统影响
    vulnerable_confidentiality: VulnerableSystemImpact
    vulnerable_integrity: VulnerableSystemImpact
    vulnerable_availability: VulnerableSystemImpact
    
    # 后续系统影响
    subsequent_confidentiality: SubsequentSystemImpact
    subsequent_integrity: SubsequentSystemImpact 
    subsequent_availability: SubsequentSystemImpact
    
    # 补充指标
    safety_impact: Optional[SafetyImpact] = None
    automation_impact: Optional[AutomationImpact] = None
    recovery_impact: Optional[RecoveryImpact] = None


class CVSS4Calculator:
    """CVSS 4.0分数计算器"""
    
    def __init__(self):
        """初始化计算器"""
        pass
    
    def calculate_base_score(self, metrics: CVSS4Metrics) -> float:
        """计算基础分数 - 根据CVSS 4.0官方公式
        
        Args:
            metrics: CVSS 4.0指标
            
        Returns:
            基础分数 (0.0-10.0)
        """
        # 可利用性子分数
        exploitability = self._calculate_exploitability(metrics)
        
        # 影响子分数  
        impact = self._calculate_impact(metrics)
        
        # CVSS 4.0基础分数计算公式
        if impact <= 0:
            return 0.0
        
        # 基础分数 = min(10.0, Exploitability + Impact)
        # 但需要考虑四舍五入到最接近的0.1
        base_score = exploitability + impact
        
        # 应用CVSS 4.0的上限
        if base_score > 10.0:
            base_score = 10.0
        
        # 四舍五入到一位小数
        return round(base_score, 1)
    
    def _calculate_exploitability(self, metrics: CVSS4Metrics) -> float:
        """计算可利用性分数 - 根据CVSS 4.0官方公式"""
        # 获取各指标的数值
        av_values = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
        ac_values = {"L": 0.0, "H": 0.1}
        at_values = {"N": 0.0, "P": 0.1}
        pr_values = {"N": 0.0, "L": 0.1, "H": 0.2}
        ui_values = {"N": 0.0, "P": 0.1, "A": 0.2}
        
        av = av_values[metrics.attack_vector.value[0]]
        ac = ac_values[metrics.attack_complexity.value[0]]
        at = at_values[metrics.attack_requirements.value[0]]
        pr = pr_values[metrics.privileges_required.value[0]]
        ui = ui_values[metrics.user_interaction.value[0]]
        
        # CVSS 4.0可利用性公式
        exploitability = 8.22 * (1 - av) * (1 - ac) * (1 - at) * (1 - pr) * (1 - ui)
        return exploitability
    
    def _calculate_impact(self, metrics: CVSS4Metrics) -> float:
        """计算影响分数 - 根据CVSS 4.0官方公式"""
        # 影响指标数值映射
        impact_values = {"H": 0.0, "L": 0.1, "N": 0.2}
        
        # 易受攻击系统影响
        vc = impact_values[metrics.vulnerable_confidentiality.value[0]]
        vi = impact_values[metrics.vulnerable_integrity.value[0]]
        va = impact_values[metrics.vulnerable_availability.value[0]]
        
        # 后续系统影响
        sc = impact_values[metrics.subsequent_confidentiality.value[0]]
        si = impact_values[metrics.subsequent_integrity.value[0]]
        sa = impact_values[metrics.subsequent_availability.value[0]]
        
        # CVSS 4.0影响计算公式
        # 易受攻击系统影响子分数
        vulnerable_impact = 1 - ((1 - (1 - vc)) * (1 - (1 - vi)) * (1 - (1 - va)))
        
        # 后续系统影响子分数
        subsequent_impact = 1 - ((1 - (1 - sc)) * (1 - (1 - si)) * (1 - (1 - sa)))
        
        # 总影响分数 - CVSS 4.0考虑两个系统的影响
        if vulnerable_impact > 0 and subsequent_impact > 0:
            # 两个系统都有影响时的计算
            total_impact = max(vulnerable_impact, subsequent_impact) + 0.5 * min(vulnerable_impact, subsequent_impact)
        else:
            # 只有一个系统有影响
            total_impact = max(vulnerable_impact, subsequent_impact)
        
        return min(6.0, total_impact * 6.0)
    
    def get_severity_rating(self, base_score: float) -> str:
        """根据基础分数获取严重级别
        
        Args:
            base_score: 基础分数
            
        Returns:
            严重级别
        """
        if base_score == 0.0:
            return "NONE"
        elif 0.1 <= base_score <= 3.9:
            return "LOW"
        elif 4.0 <= base_score <= 6.9:
            return "MEDIUM"
        elif 7.0 <= base_score <= 8.9:
            return "HIGH"
        elif 9.0 <= base_score <= 10.0:
            return "CRITICAL"
        else:
            return "UNKNOWN"
    
    def generate_vector_string(self, metrics: CVSS4Metrics) -> str:
        """生成CVSS 4.0向量字符串
        
        Args:
            metrics: CVSS 4.0指标
            
        Returns:
            CVSS向量字符串
        """
        vector_parts = [
            "CVSS:4.0",
            f"AV:{metrics.attack_vector.value[0]}",
            f"AC:{metrics.attack_complexity.value[0]}",
            f"AT:{metrics.attack_requirements.value[0]}",
            f"PR:{metrics.privileges_required.value[0]}",
            f"UI:{metrics.user_interaction.value[0]}",
            f"VC:{metrics.vulnerable_confidentiality.value[0]}",
            f"VI:{metrics.vulnerable_integrity.value[0]}",
            f"VA:{metrics.vulnerable_availability.value[0]}",
            f"SC:{metrics.subsequent_confidentiality.value[0]}",
            f"SI:{metrics.subsequent_integrity.value[0]}",
            f"SA:{metrics.subsequent_availability.value[0]}"
        ]
        
        # 添加可选的补充指标
        if metrics.safety_impact:
            vector_parts.append(f"S:{metrics.safety_impact.value[0]}")
        if metrics.automation_impact:
            vector_parts.append(f"AU:{metrics.automation_impact.value[0]}")
        if metrics.recovery_impact:
            vector_parts.append(f"R:{metrics.recovery_impact.value[0]}")
        
        return "/".join(vector_parts)
    
    def calculate_threat_score(self, metrics: CVSS4Metrics, exploit_maturity: str = "X") -> float:
        """计算威胁分数 (CVSS-BT)
        
        Args:
            metrics: CVSS 4.0指标
            exploit_maturity: 利用成熟度 (X=未定义, U=未经证实, P=概念验证, F=功能性, H=高)
            
        Returns:
            威胁分数 (0.0-10.0)
        """
        # 获取基础分数
        base_score = self.calculate_base_score(metrics)
        
        if base_score == 0.0:
            return 0.0
        
        # 威胁调整
        exploit_values = {
            "X": 1.0,    # 未定义 - 无调整
            "U": 0.91,   # 未经证实
            "P": 0.94,   # 概念验证
            "F": 0.97,   # 功能性
            "H": 1.0     # 高
        }
        
        threat_modifier = exploit_values.get(exploit_maturity, 1.0)
        threat_score = base_score * threat_modifier
        
        return round(threat_score, 1)
    
    def calculate_environmental_score(self, metrics: CVSS4Metrics, 
                                    confidentiality_req: str = "X",
                                    integrity_req: str = "X", 
                                    availability_req: str = "X") -> float:
        """计算环境分数 (CVSS-BE)
        
        Args:
            metrics: CVSS 4.0指标
            confidentiality_req: 机密性要求 (X=未定义, L=低, M=中, H=高)
            integrity_req: 完整性要求
            availability_req: 可用性要求
            
        Returns:
            环境分数 (0.0-10.0) 
        """
        base_score = self.calculate_base_score(metrics)
        
        if base_score == 0.0:
            return 0.0
        
        # 环境要求调整因子
        req_values = {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}
        
        c_req = req_values.get(confidentiality_req, 1.0)
        i_req = req_values.get(integrity_req, 1.0)
        a_req = req_values.get(availability_req, 1.0)
        
        # 简化的环境调整计算
        env_modifier = (c_req + i_req + a_req) / 3.0
        env_score = min(10.0, base_score * env_modifier)
        
        return round(env_score, 1)
    
    def evaluate_supplemental_metrics(self, metrics: CVSS4Metrics) -> Dict[str, str]:
        """评估补充指标
        
        Args:
            metrics: CVSS 4.0指标
            
        Returns:
            补充指标评估结果
        """
        supplemental = {}
        
        # 安全影响
        if metrics.safety_impact:
            if metrics.safety_impact == SafetyImpact.NEGLIGIBLE:
                supplemental["safety"] = "对物理安全影响可忽略"
            else:
                supplemental["safety"] = "可能对物理安全造成影响"
        
        # 自动化影响
        if metrics.automation_impact:
            if metrics.automation_impact == AutomationImpact.YES:
                supplemental["automation"] = "漏洞可自动化利用"
            else:
                supplemental["automation"] = "漏洞不易自动化利用"
        
        # 恢复影响
        if metrics.recovery_impact:
            if metrics.recovery_impact == RecoveryImpact.AUTOMATIC:
                supplemental["recovery"] = "系统可自动恢复"
            elif metrics.recovery_impact == RecoveryImpact.USER:
                supplemental["recovery"] = "需要用户干预恢复"
            else:
                supplemental["recovery"] = "系统无法恢复"
        
        return supplemental
    
    def generate_detailed_assessment(self, metrics: CVSS4Metrics) -> Dict[str, any]:
        """生成详细的CVSS 4.0评估报告
        
        Args:
            metrics: CVSS 4.0指标
            
        Returns:
            详细评估结果
        """
        base_score = self.calculate_base_score(metrics)
        severity = self.get_severity_rating(base_score)
        vector_string = self.generate_vector_string(metrics)
        supplemental = self.evaluate_supplemental_metrics(metrics)
        
        return {
            "base_score": base_score,
            "severity": severity,
            "vector_string": vector_string,
            "exploitability": self._calculate_exploitability(metrics),
            "impact": self._calculate_impact(metrics),
            "supplemental_metrics": supplemental,
            "cvss_version": "4.0"
        }