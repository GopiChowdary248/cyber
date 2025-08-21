import asyncio
import re
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import json
import logging
from urllib.parse import urlparse, urljoin, parse_qs
import aiohttp
import asyncio

logger = logging.getLogger(__name__)


class CrawlStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class CrawlTarget:
    url: str
    depth: int = 0
    parent_url: Optional[str] = None
    discovered_at: datetime = None
    
    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.utcnow()


@dataclass
class CrawlResult:
    url: str
    status_code: int
    content_type: str
    title: str
    links: List[str]
    forms: List[Dict]
    javascript: List[str]
    cookies: Dict
    headers: Dict
    body_length: int
    crawl_time: datetime = None
    
    def __post_init__(self):
        if self.crawl_time is None:
            self.crawl_time = datetime.utcnow()


class RobotsTxtParser:
    """Parser for robots.txt files."""
    
    def __init__(self):
        self.rules: Dict[str, List[str]] = {}
        self.sitemaps: List[str] = []
        self.crawl_delay: int = 0
    
    async def parse(self, robots_content: str, base_url: str) -> None:
        """Parse robots.txt content."""
        lines = robots_content.split('\n')
        current_user_agent = '*'
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if ':' in line:
                directive, value = line.split(':', 1)
                directive = directive.strip().lower()
                value = value.strip()
                
                if directive == 'user-agent':
                    current_user_agent = value
                    if current_user_agent not in self.rules:
                        self.rules[current_user_agent] = []
                
                elif directive == 'disallow':
                    if current_user_agent in self.rules:
                        self.rules[current_user_agent].append(value)
                
                elif directive == 'allow':
                    if current_user_agent in self.rules:
                        self.rules[current_user_agent].append(f"!{value}")
                
                elif directive == 'crawl-delay':
                    try:
                        self.crawl_delay = int(value)
                    except ValueError:
                        pass
                
                elif directive == 'sitemap':
                    self.sitemaps.append(value)
    
    def is_allowed(self, url: str, user_agent: str = '*') -> bool:
        """Check if a URL is allowed to be crawled."""
        # Check specific user agent rules first
        if user_agent in self.rules:
            for rule in self.rules[user_agent]:
                if rule.startswith('!'):
                    # Allow rule
                    if url.startswith(rule[1:]):
                        return True
                else:
                    # Disallow rule
                    if url.startswith(rule):
                        return False
        
        # Check wildcard rules
        if '*' in self.rules:
            for rule in self.rules['*']:
                if rule.startswith('!'):
                    if url.startswith(rule[1:]):
                        return True
                else:
                    if url.startswith(rule):
                        return False
        
        return True


class ScopeValidator:
    """Validates URLs against crawl scope rules."""
    
    def __init__(self, scope_config: Dict):
        self.include_patterns = scope_config.get('include_patterns', [])
        self.exclude_patterns = scope_config.get('exclude_patterns', [])
        self.allowed_ports = scope_config.get('allowed_ports', [80, 443])
        self.allowed_filetypes = scope_config.get('allowed_filetypes', [])
        self.max_depth = scope_config.get('max_depth', 3)
    
    def is_in_scope(self, url: str, depth: int = 0) -> bool:
        """Check if URL is within crawl scope."""
        if depth > self.max_depth:
            return False
        
        parsed = urlparse(url)
        
        # Check port
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        if port not in self.allowed_ports:
            return False
        
        # Check file type
        if self.allowed_filetypes:
            path = parsed.path.lower()
            if not any(path.endswith(ft) for ft in self.allowed_filetypes):
                return False
        
        # Check include patterns
        if self.include_patterns:
            if not any(re.search(pattern, url) for pattern in self.include_patterns):
                return False
        
        # Check exclude patterns
        if self.exclude_patterns:
            if any(re.search(pattern, url) for pattern in self.exclude_patterns):
                return False
        
        return True


class CrawlerEngine:
    """Main crawler engine that orchestrates web crawling."""
    
    def __init__(self):
        self.active_crawls: Dict[str, Dict] = {}
        self.robots_cache: Dict[str, RobotsTxtParser] = {}
        self.discovered_urls: Set[str] = set()
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def start_crawl(self, project_id: str, start_url: str, scope_config: Dict, crawl_config: Dict) -> str:
        """Start a new crawl."""
        crawl_id = f"crawl_{project_id}_{int(datetime.utcnow().timestamp())}"
        
        self.active_crawls[crawl_id] = {
            "project_id": project_id,
            "start_url": start_url,
            "scope_config": scope_config,
            "crawl_config": crawl_config,
            "status": CrawlStatus.RUNNING,
            "started_at": datetime.utcnow(),
            "results": [],
            "queue": [CrawlTarget(start_url, depth=0)],
            "visited": set(),
            "progress": 0,
            "total_discovered": 0
        }
        
        # Initialize session
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers={'User-Agent': 'CyberShield Crawler/1.0'}
            )
        
        # Start crawl in background
        asyncio.create_task(self._run_crawl(crawl_id))
        
        return crawl_id
    
    async def stop_crawl(self, crawl_id: str) -> bool:
        """Stop a running crawl."""
        if crawl_id in self.active_crawls:
            self.active_crawls[crawl_id]["status"] = CrawlStatus.PAUSED
            return True
        return False
    
    async def get_crawl_status(self, crawl_id: str) -> Optional[Dict]:
        """Get current crawl status."""
        return self.active_crawls.get(crawl_id)
    
    async def _run_crawl(self, crawl_id: str):
        """Run the actual crawl."""
        crawl = self.active_crawls[crawl_id]
        scope_validator = ScopeValidator(crawl["scope_config"])
        
        try:
            while crawl["queue"] and crawl["status"] == CrawlStatus.RUNNING:
                target = crawl["queue"].pop(0)
                
                if target.url in crawl["visited"]:
                    continue
                
                # Check scope
                if not scope_validator.is_in_scope(target.url, target.depth):
                    continue
                
                # Check robots.txt
                if not await self._check_robots_txt(target.url):
                    continue
                
                # Crawl the URL
                result = await self._crawl_url(target.url)
                if result:
                    crawl["results"].append(result)
                    crawl["visited"].add(target.url)
                    
                    # Extract new links
                    new_targets = await self._extract_targets(result, target.depth + 1)
                    for new_target in new_targets:
                        if new_target.url not in crawl["visited"] and new_target.url not in [t.url for t in crawl["queue"]]:
                            if scope_validator.is_in_scope(new_target.url, new_target.depth):
                                crawl["queue"].append(new_target)
                    
                    crawl["total_discovered"] = len(crawl["visited"]) + len(crawl["queue"])
                    crawl["progress"] = int(len(crawl["visited"]) / (len(crawl["visited"]) + len(crawl["queue"])) * 100)
                
                # Rate limiting
                await asyncio.sleep(crawl["crawl_config"].get("delay", 1))
            
            crawl["status"] = CrawlStatus.COMPLETED
            crawl["completed_at"] = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Crawl {crawl_id} failed: {e}")
            crawl["status"] = CrawlStatus.FAILED
            crawl["error"] = str(e)
    
    async def _check_robots_txt(self, url: str) -> bool:
        """Check robots.txt for the given URL."""
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        
        if robots_url in self.robots_cache:
            robots_parser = self.robots_cache[robots_url]
        else:
            try:
                async with self.session.get(robots_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        robots_parser = RobotsTxtParser()
                        await robots_parser.parse(content, robots_url)
                        self.robots_cache[robots_url] = robots_parser
                    else:
                        return True  # No robots.txt, allow crawling
            except Exception:
                return True  # Error fetching robots.txt, allow crawling
        
        return robots_parser.is_allowed(url)
    
    async def _crawl_url(self, url: str) -> Optional[CrawlResult]:
        """Crawl a single URL and return results."""
        try:
            async with self.session.get(url) as response:
                content = await response.text()
                headers = dict(response.headers)
                
                # Extract title
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                title = title_match.group(1) if title_match else "No Title"
                
                # Extract links
                links = re.findall(r'href=["\']([^"\']+)["\']', content)
                absolute_links = [urljoin(url, link) for link in links]
                
                # Extract forms
                forms = []
                form_matches = re.finditer(r'<form[^>]*>(.*?)</form>', content, re.IGNORECASE | re.DOTALL)
                for form_match in form_matches:
                    form_html = form_match.group(0)
                    action_match = re.search(r'action=["\']([^"\']+)["\']', form_html)
                    method_match = re.search(r'method=["\']([^"\']+)["\']', form_html)
                    
                    forms.append({
                        "action": urljoin(url, action_match.group(1)) if action_match else url,
                        "method": method_match.group(1).upper() if method_match else "GET",
                        "html": form_html[:500]  # Truncate for storage
                    })
                
                # Extract JavaScript
                js_matches = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', content)
                js_inline = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL)
                javascript = js_matches + [js[:100] for js in js_inline]  # Truncate inline JS
                
                return CrawlResult(
                    url=url,
                    status_code=response.status,
                    content_type=headers.get('content-type', ''),
                    title=title,
                    links=absolute_links,
                    forms=forms,
                    javascript=javascript,
                    cookies=dict(response.cookies),
                    headers=headers,
                    body_length=len(content)
                )
        
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
            return None
    
    async def _extract_targets(self, result: CrawlResult, depth: int) -> List[CrawlTarget]:
        """Extract new crawl targets from crawl results."""
        targets = []
        
        for link in result.links:
            if link not in self.discovered_urls:
                self.discovered_urls.add(link)
                targets.append(CrawlTarget(
                    url=link,
                    depth=depth,
                    parent_url=result.url
                ))
        
        return targets
    
    async def get_crawl_results(self, crawl_id: str) -> List[CrawlResult]:
        """Get all results from a crawl."""
        crawl = self.active_crawls.get(crawl_id)
        if crawl:
            return crawl.get("results", [])
        return []
    
    async def get_all_results(self, project_id: str) -> List[CrawlResult]:
        """Get all results from all crawls in a project."""
        all_results = []
        for crawl in self.active_crawls.values():
            if crawl["project_id"] == project_id:
                all_results.extend(crawl.get("results", []))
        return all_results
    
    async def cleanup(self):
        """Clean up resources."""
        if self.session:
            await self.session.close()


# Global crawler engine instance
crawler_engine = CrawlerEngine()
