#!/usr/bin/env python3
"""
CTF Similar Challenge Search Script
Uses Tavily API for search and content extraction
"""

import os
import re
import sys

# Configuration
MAX_WORKERS = 5

# Tavily API Configuration
TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY", "")

def tavily_search(query, max_results=10):
    """
    Search using Tavily API
    POST https://api.tavily.com/search
    """
    try:
        import requests

        url = "https://api.tavily.com/search"
        headers = {
            "Authorization": f"Bearer {TAVILY_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "query": query,
            "max_results": max_results,
            "include_answer": True,
            "include_raw_content": False
        }

        response = requests.post(url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()

    except ImportError:
        print("[!] requests package not installed. Install with: pip install requests")
        return None
    except Exception as e:
        print(f"[!] Tavily search error: {e}")
        return None

def tavily_extract(urls):
    """
    Extract content from URLs using Tavily Extract API
    POST https://api.tavily.com/extract
    """
    try:
        import requests

        url = "https://api.tavily.com/extract"
        headers = {
            "Authorization": f"Bearer {TAVILY_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "urls": urls if isinstance(urls, list) else [urls]
        }

        response = requests.post(url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()

    except ImportError:
        print("[!] requests package not installed. Install with: pip install requests")
        return None
    except Exception as e:
        print(f"[!] Tavily extract error: {e}")
        return None

def main():
    if not TAVILY_API_KEY:
        print("Error: TAVILY_API_KEY environment variable is not set.")
        print("Get a key from https://tavily.com and export it:")
        print("  export TAVILY_API_KEY='tvly-...'")
        sys.exit(1)

    if len(sys.argv) < 3:
        print("Usage:")
        print("  python3 search.py search <keyword>")
        print("  python3 search.py extract <url1> [url2] ...")
        print()
        print("Examples:")
        print("  python3 search.py search 'SSRF vulnerability'")
        print("  python3 search.py extract 'https://example.com/article1' 'https://example.com/article2'")
        sys.exit(1)

    # Detect code/identifier queries (exempt from word limit):
    # Contains code-like patterns: parens, braces, equals, colons, dots,
    # underscores, quotes
    action = sys.argv[1]

    if action == "search":
        if len(sys.argv) < 3:
            print("Error: search requires a keyword")
            sys.exit(1)

        keyword = " ".join(sys.argv[2:])
        word_count = len(keyword.split())

        code_pat = r'[(){}\[\]=\':"_.]|def |class |import |from |return '
        is_code_query = bool(re.search(code_pat, keyword))

        if not is_code_query and word_count > 3:
            print("=" * 60)
            print("ERROR: Non-code search query exceeds 3-word limit.")
            print("=" * 60)
            print(f"Query ({word_count} words): {keyword}")
            print()
            print("For non-code searches, use at most 3 distinctive keywords.")
            print("Examples:")
            print("  ✅ 'DASCTF URL Storage'     (3 words)")
            print("  ✅ 'HGAME baby web'         (3 words)")
            print("  ❌ 'HGAME 2024 baby web challenge' (5 words — drop filler)")
            print()
            print("Code snippets, error messages, and unique identifiers are exempt.")
            print("If this IS a code/identifier query, include code-like characters")
            print("(parens, braces, equals, colons) to bypass the limit.")
            sys.exit(1)

        print("=" * 60)
        print("Tavily Search")
        print("=" * 60)
        print(f"Query: {keyword}")
        print()

        result = tavily_search(keyword, max_results=10)

        if not result:
            print("Search failed.")
            return

        # Print answer if available
        if 'answer' in result and result['answer']:
            print("Answer:")
            print(result['answer'])
            print()

        # Print search results
        if 'results' in result:
            print(f"Results ({len(result['results'])} found):")
            print("-" * 60)

            for i, item in enumerate(result['results'], 1):
                print(f"{i}. {item.get('title', 'No title')}")
                print(f"   URL: {item.get('url', '')}")
                if 'content' in item:
                    content = item['content'][:300]
                    print(f"   Content: {content}...")
                print()

        # Print usage info
        if 'usage' in result:
            print("-" * 60)
            print(f"Credits used: {result['usage'].get('credits', 'N/A')}")

    elif action == "extract":
        if len(sys.argv) < 3:
            print("Error: extract requires at least one URL")
            sys.exit(1)

        urls = sys.argv[2:]

        print("=" * 60)
        print("Tavily Extract")
        print("=" * 60)
        print(f"URLs to extract: {len(urls)}")
        print()

        result = tavily_extract(urls)

        if not result:
            print("Extract failed.")
            return

        # Print extracted content
        if 'results' in result:
            print(f"Extracted ({len(result['results'])} URLs):")
            print("-" * 60)

            for i, item in enumerate(result['results'], 1):
                print(f"{i}. URL: {item.get('url', '')}")
                if 'raw_content' in item:
                    content = item['raw_content'][:1000]
                    print("   Content:")
                    print(f"   {content}")
                if 'images' in item and item['images']:
                    print(f"   Images: {len(item['images'])} found")
                print()

        # Print failed results
        if 'failed_results' in result and result['failed_results']:
            print("Failed to extract:")
            for item in result['failed_results']:
                print(f"  - {item}")

        # Print usage info
        if 'usage' in result:
            print("-" * 60)
            print(f"Credits used: {result['usage'].get('credits', 'N/A')}")

    else:
        print(f"Unknown action: {action}")
        print("Use 'search' or 'extract'")
        sys.exit(1)

    print()
    print("=" * 60)

if __name__ == "__main__":
    main()
