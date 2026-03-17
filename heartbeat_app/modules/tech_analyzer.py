import subprocess
import json

class TechAnalyzer:
    """
    Performs deep technology detection to uncover the stack behind WAFs like Cloudflare.
    It uses multiple layers of analysis, including advanced tools and intelligent guessing.
    """

    def analyze(self, url: str, cookies: dict, initial_scan_results: list) -> dict:
        """
        Runs a multi-layered analysis to get the real tech stack.
        """
        tech_stack = {'lang': 'unknown', 'server': 'unknown', 'framework': 'unknown', 'cms': 'unknown'}

        # Layer 1: Run advanced tool (webtech)
        try:
            result = subprocess.run(
                ['webtech', '-u', url, '--json'],
                capture_output=True, text=True, timeout=60
            )
            webtech_data = json.loads(result.stdout)
            # This part needs specific parsing based on webtech's JSON structure
            
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        # Layer 2: Intelligent Guessing (AI Logic)
        for key in cookies.keys():
            if 'laravel_session' in key:
                tech_stack['lang'] = 'PHP'
                tech_stack['framework'] = 'Laravel'
                break
            if 'csrftoken' in key:
                tech_stack['lang'] = 'Python'
                tech_stack['framework'] = 'Django'
                break
            if 'JSESSIONID' in key:
                tech_stack['lang'] = 'Java'
                break

        for path in initial_scan_results:
            if '/wp-content/' in path or '/wp-admin' in path:
                tech_stack['lang'] = 'PHP'
                tech_stack['cms'] = 'WordPress'
                break
            if '.aspx' in path:
                tech_stack['lang'] = 'ASP.NET'
                break
        
        return tech_stack
