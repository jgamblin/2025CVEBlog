#!/usr/bin/env python3
"""
Enrich 2025 CVE Data Review Blog with AI-Generated Text
Uses Google Gemini API to improve and expand blog text while keeping statistics intact.
"""

import os
import re
import json
import time
from pathlib import Path
from datetime import datetime

try:
    import google.generativeai as genai
except ImportError:
    print("ERROR: google-generativeai not installed.")
    print("Install with: pip install google-generativeai")
    exit(1)

# Configuration
INPUT_FILE = Path("blog.md")
OUTPUT_FILE = Path("blog_enriched.md")
BACKUP_FILE = Path("blog_original.md")

# Gemini model selection
MODEL_NAME = "gemini-2.0-flash"  # Updated model name

# Rate limiting removed - using paid tier

def get_api_key():
    """Get Gemini API key from environment variable"""
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    
    if not api_key:
        print("ERROR: No API key found.")
        print("\nTo use this script, set your Gemini API key:")
        print("  export GEMINI_API_KEY='your-api-key-here'")
        print("\nGet an API key at: https://makersuite.google.com/app/apikey")
        return None
    
    return api_key

def extract_sections(markdown_text):
    """Extract sections from markdown for individual enhancement"""
    sections = []
    current_section = {"title": "Header", "content": "", "level": 0}
    
    for line in markdown_text.split('\n'):
        # Check for headers
        if line.startswith('#'):
            # Save previous section
            if current_section["content"].strip():
                sections.append(current_section.copy())
            
            # Determine header level
            level = len(line) - len(line.lstrip('#'))
            title = line.lstrip('#').strip()
            current_section = {"title": title, "content": line + '\n', "level": level}
        else:
            current_section["content"] += line + '\n'
    
    # Don't forget last section
    if current_section["content"].strip():
        sections.append(current_section)
    
    return sections

def should_enhance_section(section):
    """Determine if a section should be enhanced with AI"""
    title_lower = section["title"].lower()
    
    # Skip metadata and methodology sections (keep factual)
    skip_keywords = [
        "methodology", "data sources", "thank you", "data collected"
    ]
    
    # Skip sections that are primarily tables or images
    content = section["content"]
    table_lines = len([l for l in content.split('\n') if l.strip().startswith('|')])
    total_lines = len([l for l in content.split('\n') if l.strip()])
    
    if total_lines > 0 and table_lines / total_lines > 0.6:
        return False
    
    return not any(kw in title_lower for kw in skip_keywords)

def create_enhancement_prompt(section_title, section_content):
    """Create a prompt for enhancing a specific section with Jerry Gamblin voice"""
    return f"""You are Jerry Gamblin. You write the popular 'Curiosity in Practice' security blog.

YOUR VOICE:
- Direct & Personal: Use 'I' and 'We'. (e.g., 'I noticed a trend...' or 'We saw a massive spike...').
- Data-First: Never use fluffy adjectives like 'staggering', 'unprecedented', 'landscape', or 'realm'. Let the numbers speak.
- Concise: Short paragraphs. No filler. If a chart explains it, don't describe the bars, explain the implication.

TASK: Enhance the provided section. Keep ALL statistics and markdown tables exactly as they are.

ADD MARKDOWN LINKS for technical terms:
- Link CWEs to: https://cwe.mitre.org/data/definitions/{{number}}.html
  Example: [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
- Link Vendors/Products to: https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor={{name}}
  Example: [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft)

RULES:
1. Keep ALL statistics, numbers, and data points EXACTLY as they are
2. Keep ALL markdown formatting (headers, tables, images) intact
3. Do NOT change image paths or table data
4. Do NOT increase text length by more than 10%
5. Return the enhanced markdown only, no explanations

SECTION TITLE: {section_title}

CURRENT CONTENT:
{section_content}

ENHANCED CONTENT:"""

def enhance_section_with_gemini(model, section):
    """Use Gemini to enhance a single section"""
    if not should_enhance_section(section):
        return section["content"]
    
    prompt = create_enhancement_prompt(section["title"], section["content"])
    
    max_retries = 3
    retry_delay = 15  # seconds
    
    for attempt in range(max_retries):
        try:
            response = model.generate_content(
                prompt,
                generation_config={
                    "temperature": 0.5,  # Conservative for analytical tone
                    "max_output_tokens": 2048,
                }
            )
            
            enhanced = response.text.strip()
            
            # Validation: ensure key statistics are preserved
            # Extract all numbers from original and enhanced
            original_numbers = set(re.findall(r'\d{1,3}(?:,\d{3})*(?:\.\d+)?', section["content"]))
            enhanced_numbers = set(re.findall(r'\d{1,3}(?:,\d{3})*(?:\.\d+)?', enhanced))
            
            # Check if we lost any significant numbers
            lost_numbers = original_numbers - enhanced_numbers
            if lost_numbers:
                print(f"    ⚠ Warning: Some numbers may have changed in '{section['title']}'")
                # Fall back to original if significant data loss detected
                if len(lost_numbers) > 3:
                    print(f"    ↳ Reverting to original (too many number changes)")
                    return section["content"]
            
            return enhanced
            
        except Exception as e:
            error_str = str(e)
            if "429" in error_str or "quota" in error_str.lower():
                if attempt < max_retries - 1:
                    wait_time = retry_delay * (attempt + 1)
                    print(f"    ⏳ Rate limited, waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                    continue
            print(f"    ✗ Error enhancing '{section['title']}': {e}")
            return section["content"]
    
    return section["content"]

def enhance_executive_summary(model, blog_text):
    """Specifically enhance the executive summary with Jerry Gamblin voice"""
    prompt = f"""You are Jerry Gamblin. You write the popular 'Curiosity in Practice' security blog.

YOUR VOICE:
- Direct & Personal: Use 'I' and 'We'. (e.g., 'I noticed a trend...' or 'We saw a massive spike...').
- Data-First: Never use fluffy adjectives like 'staggering', 'unprecedented', 'landscape', or 'realm'. Let the numbers speak.
- Concise: Short paragraphs. No filler.

Create an executive summary that:
1. Opens with the key finding immediately (no generic intros)
2. Uses personal voice ('I analyzed...', 'We see that...')
3. Highlights the most important 2025 data points
4. Maintains all original statistics EXACTLY
5. Does NOT expand beyond 15% of original length
6. Links CWEs to https://cwe.mitre.org/data/definitions/{{number}}.html
7. Links vendors to https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor={{name}}

Original executive summary to enhance (keep all statistics):
{blog_text}

Write the enhanced executive summary in markdown:"""
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"temperature": 0.6, "max_output_tokens": 1024}
        )
        return response.text.strip()
    except Exception as e:
        print(f"  ✗ Error enhancing executive summary: {e}")
        return blog_text

def enhance_conclusions(model, blog_text, stats_context):
    """Enhance the conclusions with Jerry Gamblin voice"""
    prompt = f"""You are Jerry Gamblin. You write the popular 'Curiosity in Practice' security blog.

YOUR VOICE:
- Direct & Personal: Use 'I' and 'We'. (e.g., 'I expect...', 'What I'm watching...').
- Data-First: Never use fluffy adjectives like 'staggering', 'unprecedented', 'landscape', or 'realm'. Let the numbers speak.
- Concise: Short paragraphs. No filler.

The blog has covered:
{stats_context}

Current conclusions section:
{blog_text}

Enhance the conclusions to:
1. Summarize key findings in personal voice
2. Add 2-3 forward-looking predictions for 2026 based on trends
3. Provide actionable insights for security teams
4. Keep all original statistics intact
5. Do NOT expand beyond 15% of original length
6. Link CWEs to https://cwe.mitre.org/data/definitions/{{number}}.html
7. Link vendors to https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor={{name}}

Write enhanced conclusions in markdown:"""
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"temperature": 0.6, "max_output_tokens": 1500}
        )
        return response.text.strip()
    except Exception as e:
        print(f"  ✗ Error enhancing conclusions: {e}")
        return blog_text

def main():
    print("=" * 60)
    print("2025 CVE Blog Enrichment with Gemini AI")
    print("=" * 60)
    
    # Check for API key
    api_key = get_api_key()
    if not api_key:
        return
    
    # Check for input file
    if not INPUT_FILE.exists():
        print(f"\nERROR: {INPUT_FILE} not found.")
        print("Run 04_generate_blog.py first to create the blog.")
        return
    
    # Read original blog
    print(f"\n[1/4] Reading {INPUT_FILE}...")
    with open(INPUT_FILE, 'r') as f:
        original_blog = f.read()
    
    # Backup original
    print(f"[2/4] Creating backup at {BACKUP_FILE}...")
    with open(BACKUP_FILE, 'w') as f:
        f.write(original_blog)
    
    # Initialize Gemini
    print(f"[3/4] Initializing Gemini ({MODEL_NAME})...")
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(MODEL_NAME)
    
    # Extract and enhance sections
    print("[4/4] Enhancing blog sections...")
    sections = extract_sections(original_blog)
    
    enhanced_sections = []
    total_sections = len([s for s in sections if should_enhance_section(s)])
    enhanced_count = 0
    
    for i, section in enumerate(sections):
        section_name = section["title"][:40] + "..." if len(section["title"]) > 40 else section["title"]
        
        if should_enhance_section(section):
            enhanced_count += 1
            print(f"  ✓ Enhancing ({enhanced_count}/{total_sections}): {section_name}")
            enhanced_content = enhance_section_with_gemini(model, section)
            enhanced_sections.append(enhanced_content)
        else:
            print(f"  - Keeping: {section_name}")
            enhanced_sections.append(section["content"])
    
    # Combine enhanced sections
    enhanced_blog = '\n'.join(enhanced_sections)
    
    # Clean up any double line breaks that might have been introduced
    enhanced_blog = re.sub(r'\n{4,}', '\n\n\n', enhanced_blog)
    
    # Save enhanced blog
    print(f"\nSaving enhanced blog to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, 'w') as f:
        f.write(enhanced_blog)
    
    print("\n" + "=" * 60)
    print("ENRICHMENT COMPLETE!")
    print("=" * 60)
    print(f"\n✓ Original blog backed up to: {BACKUP_FILE}")
    print(f"✓ Enhanced blog saved to: {OUTPUT_FILE}")
    print(f"\nReview the enhanced blog before publishing.")
    print("You may want to manually review and adjust the AI-enhanced text.")

if __name__ == "__main__":
    main()
