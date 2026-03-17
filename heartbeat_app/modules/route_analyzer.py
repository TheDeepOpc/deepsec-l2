"""
Route Family Analyzer
This module provides tools to analyze a list of URLs, group them into
"route families" by generalizing their paths, and identify patterns.
For example, it clusters:
  - /articles/101, /articles/102 -> /articles/:id
  - /product?cat=5, /product?cat=8 -> /product?cat=:id
This allows the AIEngine to make strategic decisions about which parts of a
website to fuzz deeply and which to deprioritize as repetitive content.
"""
import re
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

class RouteAnalyzer:
    """Dynamically identifies and clusters URL patterns."""

    def generalize_path(self, path: str) -> str:
        """
        Converts a specific path into a generalized pattern.
        e.g., "/articles/123/edit" -> "/articles/:id/edit"
        """
        # Replace sequences of digits with :id
        generalized = re.sub(r'\b\d{4,}\b', ':longid', path) # Longer IDs first
        generalized = re.sub(r'\b\d+\b', ':id', generalized)
        # Replace common UUID patterns
        generalized = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', ':uuid', generalized, flags=re.IGNORECASE)
        # Replace base64-like strings or long hashes
        generalized = re.sub(r'\b[A-Za-z0-9+/=_-]{20,}\b', ':hash', generalized)
        return generalized

    def cluster_urls(self, urls: list[str]) -> dict[str, list[str]]:
        """
        Groups a list of URLs into families based on their generalized path
        and query parameter structure.

        Returns:
            A dictionary where keys are the family pattern (e.g., "/articles/:id")
            and values are the list of URLs belonging to that family.
        """
        families = defaultdict(list)
        for url in urls:
            parsed_url = urlparse(url)
            
            # Generalize the path part
            path_pattern = self.generalize_path(parsed_url.path)
            
            # Generalize the query part
            query_params = parse_qs(parsed_url.query)
            query_keys = sorted(query_params.keys())
            query_pattern = '&'.join(f"{key}=:val" for key in query_keys)
            
            family_key = path_pattern
            if query_pattern:
                family_key += "?" + query_pattern
            
            families[family_key].append(url)
            
        return dict(families)
