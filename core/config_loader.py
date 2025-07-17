import yaml
from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field, HttpUrl

class TargetAuthConfig(BaseModel):
    type: Literal["cookie", "jwt", "basic_auth", "oauth2"]
    value: str

class TargetConfig(BaseModel):
    url: HttpUrl
    depth: int = Field(4, gt=0)
    allowed_domains: List[str] = Field(default_factory=list)
    exclude_paths: List[str] = Field(default_factory=list)
    auth: Optional[TargetAuthConfig] = None

class ScannerConfig(BaseModel):
    concurrency: int = Field(30, gt=0)
    timeout: int = Field(8, gt=0)
    retries: int = Field(3, ge=0)
    rate_limit: int = Field(100, gt=0)
    user_agents: List[str] = Field(default_factory=list)

class VulnConfig(BaseModel):
    type: str
    parameters: List[str]
    payload_level: Literal["basic", "smart", "aggressive"] = "smart"
    detection_methods: Optional[List[str]] = None
    shell_detection: Optional[bool] = None

class AIModuleConfig(BaseModel):
    enable: bool = True
    model: str = "openai/gpt-4o-mini"
    api_key: Optional[str] = None
    proxy: Optional[HttpUrl] = None
    payload_prompt_template: str
    analysis_prompt_template: str

class ReportingConfig(BaseModel):
    format: List[Literal["html", "json", "md"]] = ["html"]
    path: str = "./reports/"

class NotificationEmailConfig(BaseModel):
    enable: bool = False
    recipients: List[str] = Field(default_factory=list)
    smtp_server: Optional[str] = None
    port: int = 587
    username: Optional[str] = None
    password: Optional[str] = None

class NotificationWebhookConfig(BaseModel):
    enable: bool = False
    url: Optional[HttpUrl] = None
    headers: Dict[str, str] = Field(default_factory=dict)

class NotificationConfig(BaseModel):
    email: NotificationEmailConfig = Field(default_factory=NotificationEmailConfig)
    webhook: NotificationWebhookConfig = Field(default_factory=NotificationWebhookConfig)

class WafBypassConfig(BaseModel):
    enable: bool = False
    strategies: List[str] = Field(default_factory=list)

class AdvancedJSReverseEngineeringConfig(BaseModel):
    enable: bool = True
    headless_browser: Literal["chromium", "firefox", "webkit"] = "chromium"

class AdvancedConfig(BaseModel):
    dry_run: bool = False
    js_reverse_engineering: AdvancedJSReverseEngineeringConfig = Field(default_factory=AdvancedJSReverseEngineeringConfig)

class RedisConfig(BaseModel):
    url: str = "redis://localhost:6379/0"

class Settings(BaseModel):
    target: TargetConfig
    scanner: ScannerConfig
    vulns: List[VulnConfig]
    ai_module: AIModuleConfig
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    notification: NotificationConfig = Field(default_factory=NotificationConfig)
    waf_bypass: WafBypassConfig = Field(default_factory=WafBypassConfig)
    advanced: AdvancedConfig = Field(default_factory=AdvancedConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)


def load_config(path: str, url_override: Optional[str] = None) -> Settings:
    """
    Loads, parses, and validates the configuration from a YAML file.
    An optional URL can be provided to override the one in the config file.
    """
    from .logger import log
    log.info(f"Loading configuration from: {path}")
    try:
        with open(path, 'r', encoding='utf-8') as f:
            raw_config = yaml.safe_load(f)

        if url_override:
            if 'target' not in raw_config:
                raw_config['target'] = {}
            raw_config['target']['url'] = url_override
        
        settings = Settings(**raw_config)
        log.info("Configuration loaded and validated successfully.")
        return settings
    except FileNotFoundError:
        log.error(f"Configuration file not found at: {path}")
        raise
    except yaml.YAMLError as e:
        log.error(f"Error parsing YAML file: {e}")
        raise
    except Exception as e:
        log.error(f"Configuration validation failed: {e}")
        raise

if __name__ == '__main__':
    # For testing purposes
    from pprint import pprint
    # This assumes you run this from the project root: python -m core.config_loader
    config = load_config('config/vuln_config.yaml')
    pprint(config.dict())
