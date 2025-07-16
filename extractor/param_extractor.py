from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup, Tag
from core.logger import log

class ParamExtractor:
    """
    Extracts potential parameters from a given URL and its content.
    """

    def extract_from_url(self, url: str) -> List[Dict[str, Any]]:
        """
        Extracts GET parameters from the URL's query string.

        Args:
            url: The URL to extract parameters from.

        Returns:
            A list of dictionaries, where each dictionary represents a parameter.
        """
        extracted_params: List[Dict[str, Any]] = []
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            for name, values in query_params.items():
                for value in values:
                    param_info = {
                        "name": name,
                        "value": value,
                        "type": "get"
                    }
                    extracted_params.append(param_info)
                    log.debug(f"Extracted GET parameter: {name}={value} from {url}")

        except Exception as e:
            log.error(f"Failed to extract parameters from {url}: {e}")
            
        return extracted_params

    def extract_from_html(self, html_content: str, base_url: str) -> List[Dict[str, Any]]:
        """
        Extracts forms and their parameters from HTML content.

        Args:
            html_content: The HTML content of the page.
            base_url: The base URL of the page, for resolving relative form actions.

        Returns:
            A list of dictionaries, where each dictionary represents a form.
        """
        forms: List[Dict[str, Any]] = []
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            for form in soup.find_all('form'):
                if isinstance(form, Tag):
                    action_val = form.get('action')
                    action = action_val if isinstance(action_val, str) else ''
                    
                    method_val = form.get('method', 'get')
                    method = method_val if isinstance(method_val, str) else 'get'
                    method = method.lower()
                    
                    form_url = urljoin(base_url, action)

                    form_params: List[Dict[str, str]] = []
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        if isinstance(input_tag, Tag):
                            name = input_tag.get('name')
                            if name and isinstance(name, str): # Only include inputs with a name
                                input_type_val = input_tag.get('type', 'text')
                                input_type = input_type_val if isinstance(input_type_val, str) else 'text'
                                form_params.append({"name": name, "type": input_type})
                    
                    if form_params:
                        form_info = {
                            "url": form_url,
                            "method": method,
                            "params": form_params,
                            "type": "form"
                        }
                        forms.append(form_info)
                        log.debug(f"Extracted form from {base_url}: method={method}, action={form_url}")

        except Exception as e:
            log.error(f"Failed to extract forms from HTML at {base_url}: {e}")

        return forms

    def extract(self, url: str, html_content: str = "") -> List[Dict[str, Any]]:
        """
        Extracts both GET parameters from the URL and form parameters from HTML.

        Args:
            url: The URL to extract parameters from.
            html_content: Optional HTML content of the page.

        Returns:
            A list of dictionaries, where each dictionary represents an injection target.
        """
        all_targets: List[Dict[str, Any]] = []
        
        url_params = self.extract_from_url(url)
        if url_params:
            all_targets.append({
                "url": url,
                "method": "get",
                "params": url_params,
                "type": "url"
            })

        if html_content:
            form_targets = self.extract_from_html(html_content, url)
            all_targets.extend(form_targets)
            
        return all_targets



