import streamlit as st
import pandas as pd
import json
import uuid
import os
import requests
import re
import plotly.express as px  # Added for advanced charting
from datetime import datetime
from streamlit_agraph import agraph, Node, Edge, Config

# --- Configuration & Setup ---
st.set_page_config(
    page_title="Ransomware Tool Matrix Visualiser",
    page_icon="☠️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Constants & URLs ---
DB_FILE = "ransomware_db.json"

REPO_BASE = "https://raw.githubusercontent.com/BushidoUK/Ransomware-Tool-Matrix/refs/heads/main"
TOOLS_CSV_URL = f"{REPO_BASE}/Tools/AllTools.csv"

# STIX Icons (Raw GitHub URLs)
ICON_BASE = "https://raw.githubusercontent.com/eclecticiq/stix-icons/master/colorRGB/normal/SVG"
ICONS = {
    "threat-actor": f"{ICON_BASE}/Threat_Actor.svg",
    "malware": f"{ICON_BASE}/Malware.svg",
    "tool": "https://raw.githubusercontent.com/eclecticiq/stix-icons/refs/heads/master/colorRGB/normal/SVG/Tool.svg",
    "attack-pattern": "https://raw.githubusercontent.com/eclecticiq/stix-icons/refs/heads/master/colorRGB/normal/SVG/Attack_Pattern.svg"
}

# Specific Names that get the Attack Pattern Icon
ATTACK_PATTERN_NAMES = [
    "Discovery", "RMM Tools", "Defense Evasion", "Credential Theft", 
    "OffSec", "Networking", "LOLBAS", "Exfiltration"
]

# Category Markdowns
CATEGORY_URLS = {
    "Discovery": f"{REPO_BASE}/Tools/Discovery.md",
    "RMM Tools": f"{REPO_BASE}/Tools/RMM-Tools.md",
    "Defense Evasion": f"{REPO_BASE}/Tools/DefenseEvasion.md",
    "Credential Theft": f"{REPO_BASE}/Tools/CredentialTheft.md",
    "OffSec": f"{REPO_BASE}/Tools/OffSec.md",
    "Networking": f"{REPO_BASE}/Tools/Networking.md",
    "LOLBAS": f"{REPO_BASE}/Tools/LOLBAS.md",
    "Exfiltration": f"{REPO_BASE}/Tools/Exfiltration.md"
}

# Group Profiles
GROUP_PROFILE_URLS = [
    f"{REPO_BASE}/GroupProfiles/Akira.md",
    f"{REPO_BASE}/GroupProfiles/BlackBasta.md",
    f"{REPO_BASE}/GroupProfiles/BlackSuit.md",
    f"{REPO_BASE}/GroupProfiles/EvilCorp.md",
    f"{REPO_BASE}/GroupProfiles/PLAY.md",
    f"{REPO_BASE}/GroupProfiles/ProphetSpider.md",
    f"{REPO_BASE}/GroupProfiles/Qilin.md",
    f"{REPO_BASE}/GroupProfiles/SafePay.md",
    f"{REPO_BASE}/GroupProfiles/ScatteredSpider.md"
]

# --- Helpers ---
def normalize_string(s):
    """Normalize string for fuzzy matching (lowercase, no spaces/special chars)"""
    if not isinstance(s, str): return ""
    return re.sub(r'[^a-z0-9]', '', s.lower())

def is_valid_tool_name(name):
    """Filter out URLs, Dates, and Junk data from tool names"""
    if not name: return False
    n = name.strip()
    if len(n) < 2: return False # Too short
    if n.isdigit(): return False # Just numbers
    
    # Check for URLs
    if re.match(r'^https?://', n, re.IGNORECASE): return False
    if re.match(r'^www\.', n, re.IGNORECASE): return False
    
    # Check for Dates
    if re.search(r'\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4}', n, re.IGNORECASE): return False
    if re.search(r'\d{4}[-/]\d{2}[-/]\d{2}', n): return False
    if re.search(r'\d{2}[-/]\d{2}[-/]\d{4}', n): return False
    
    if len(n) > 60: return False
    
    if n.lower() in ["tool", "tool name", "name", "unknown", "description", "category", "date published", "report"]: return False
    
    return True

def get_node_icon(node_type, name=None):
    """Determine STIX icon based on entity type and specific name list"""
    if node_type == "group":
        return ICONS["threat-actor"]
    elif node_type == "tool":
        # Only use Attack Pattern icon for specific high-level category nodes
        if name in ATTACK_PATTERN_NAMES:
            return ICONS["attack-pattern"]
        else:
            return ICONS["tool"]
    return ICONS["tool"]

# --- Data Management Class ---
class DataStore:
    def __init__(self):
        self.load_data()

    def load_data(self):
        if not os.path.exists(DB_FILE):
            self.data = {"groups": [], "tools": []}
            self.save_data()
        else:
            try:
                with open(DB_FILE, 'r') as f:
                    self.data = json.load(f)
            except:
                self.data = {"groups": [], "tools": []}

    def save_data(self):
        with open(DB_FILE, 'w') as f:
            json.dump(self.data, f, indent=4)

    def get_groups(self):
        return self.data.get('groups', [])

    def get_tools(self):
        return self.data.get('tools', [])
    
    def get_entity_by_id(self, entity_id):
        # Search groups
        for g in self.data.get('groups', []):
            if g['id'] == entity_id: return {**g, 'entity_type': 'Group'}
        # Search tools
        for t in self.data.get('tools', []):
            if t['id'] == entity_id: return {**t, 'entity_type': 'Tool'}
        return None

    def find_tool_id_by_name(self, name):
        name_clean = name.strip()
        for t in self.data['tools']:
            if t['name'].lower() == name_clean.lower():
                return t['id']
        
        norm_input = normalize_string(name)
        for t in self.data['tools']:
            if normalize_string(t['name']) == norm_input:
                return t['id']
        return None

    def upsert_tool(self, name, type_, description=""):
        if not is_valid_tool_name(name):
            return None
            
        existing_id = self.find_tool_id_by_name(name)
        if existing_id:
            for t in self.data['tools']:
                if t['id'] == existing_id:
                    if description and len(description) > len(t.get('description', '')): 
                        t['description'] = description
                    if type_ and type_ != "Unknown" and t.get('type') == "Unknown": 
                        t['type'] = type_
            return existing_id
        else:
            new_id = str(uuid.uuid4())
            self.data['tools'].append({
                "id": new_id,
                "name": name,
                "type": type_ if type_ else "Unknown",
                "description": description
            })
            return new_id

    def upsert_group(self, name, description, tool_names, known_tool_ids=None):
        if not name or name.lower() in ["group", "name"]: return

        group = next((g for g in self.data['groups'] if g['name'].lower() == name.lower()), None)
        
        tool_ids = []
        if tool_names:
            for t_name in tool_names:
                t_id = self.upsert_tool(t_name, "Unknown", "")
                if t_id: tool_ids.append(t_id)
        
        if known_tool_ids:
            tool_ids.extend(known_tool_ids)
            
        if group:
            if description: group['description'] = description
            existing_tools = set(group.get('tools', []))
            existing_tools.update(tool_ids)
            group['tools'] = list(existing_tools)
        else:
            self.data['groups'].append({
                "id": str(uuid.uuid4()),
                "name": name,
                "description": description,
                "tools": tool_ids
            })
        self.save_data()

    def delete_group(self, group_id):
        self.data['groups'] = [g for g in self.data['groups'] if g['id'] != group_id]
        self.save_data()

    def delete_tool(self, tool_id):
        self.data['tools'] = [t for t in self.data['tools'] if t['id'] != tool_id]
        for group in self.data['groups']:
            if 'tools' in group and tool_id in group['tools']:
                group['tools'].remove(tool_id)
        self.save_data()

if 'store' not in st.session_state:
    st.session_state.store = DataStore()
store = st.session_state.store

# --- GitHub Ingestor ---
class GitHubIngestor:
    def fetch_all_tools_csv(self):
        try:
            df = pd.read_csv(TOOLS_CSV_URL)
            count = 0
            for _, row in df.iterrows():
                name = str(row.get('Tool', row.get('Name', ''))).strip()
                cat = str(row.get('Category', 'Other')).strip()
                desc = str(row.get('Description', '')).strip()
                
                # upsert_tool handles validation
                if store.upsert_tool(name, cat, desc):
                    count += 1
            return f"Processed {count} tools from CSV."
        except Exception as e:
            return f"Error fetching CSV: {e}"

    def fetch_category_markdowns(self):
        count = 0
        for cat_name, url in CATEGORY_URLS.items():
            try:
                resp = requests.get(url)
                if resp.status_code == 200:
                    lines = resp.text.split('\n')
                    for line in lines:
                        if line.strip().startswith('|') and '---' not in line:
                            parts = [p.strip() for p in line.split('|')]
                            if len(parts) >= 3:
                                tool_name = parts[1]
                                desc = parts[2] if len(parts) > 2 else ""
                                if store.upsert_tool(tool_name, cat_name, desc):
                                    count += 1
            except Exception as e:
                print(f"Failed {cat_name}: {e}")
        return f"Scraped {count} tools from Category Markdowns."

    def fetch_group_profiles(self):
        count = 0
        all_tools = store.get_tools()
        
        for url in GROUP_PROFILE_URLS:
            try:
                resp = requests.get(url)
                if resp.status_code == 200:
                    content = resp.text
                    
                    group_name = "Unknown Group"
                    header_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
                    if header_match:
                        group_name = header_match.group(1).strip()
                    else:
                        group_name = url.split('/')[-1].replace('.md', '')

                    desc = ""
                    desc_match = re.search(r'^#\s+.+\n+(.+)', content, re.MULTILINE)
                    if desc_match:
                        desc = desc_match.group(1)[:300] + "..."

                    tools_found_names = []
                    tools_found_ids = []
                    
                    # A. Parse Bullets (Tools list)
                    tool_section = re.search(r'(?:##|###)\s+Tools.*?\n((?:[-*].*?\n)+)', content, re.IGNORECASE | re.DOTALL)
                    if tool_section:
                        bullets = tool_section.group(1)
                        raw_tools = re.findall(r'[-*]\s+(.*)', bullets)
                        for t in raw_tools:
                            clean_name = re.sub(r'\[([^\]]+)\]\(.*?\)', r'\1', t)
                            clean_name = clean_name.replace('*', '').replace('_', '').replace('`', '')
                            clean_name = clean_name.split(' - ')[0].split(' : ')[0]
                            clean_name = clean_name.strip()
                            if is_valid_tool_name(clean_name):
                                tools_found_names.append(clean_name)

                    # B. Parse Tables (Matrix format with Headers as Categories)
                    lines = content.split('\n')
                    table_headers = []
                    in_table = False
                    
                    for line in lines:
                        clean_line = line.strip()
                        if not clean_line.startswith('|'):
                            in_table = False
                            table_headers = []
                            continue
                            
                        if any(k in clean_line for k in ["Discovery", "RMM", "Defense Evasion", "Exfiltration"]):
                            raw_headers = [h.strip() for h in clean_line.strip('|').split('|')]
                            table_headers = raw_headers
                            in_table = True
                            continue
                            
                        if "---" in clean_line: continue
                        
                        if in_table and table_headers:
                            cells = [c.strip() for c in clean_line.strip('|').split('|')]
                            if len(cells) == len(table_headers):
                                for idx, cell in enumerate(cells):
                                    if not cell: continue
                                    tool_name = re.sub(r'\[([^\]]+)\]\(.*?\)', r'\1', cell)
                                    tool_name = tool_name.strip()
                                    if is_valid_tool_name(tool_name):
                                        category = table_headers[idx]
                                        if category == "RMM": category = "RMM Tools"
                                        store.upsert_tool(tool_name, category)
                                        tools_found_names.append(tool_name)

                    # C. Dictionary Attack
                    normalized_content = content.lower()
                    for db_tool in all_tools:
                        tool_name = db_tool['name']
                        if len(tool_name) < 3: continue 
                        pattern = r'\b' + re.escape(tool_name.lower()) + r'\b'
                        if re.search(pattern, normalized_content):
                            tools_found_ids.append(db_tool['id'])

                    if group_name != "Unknown Group":
                        store.upsert_group(group_name, desc, tools_found_names, tools_found_ids)
                        count += 1
            except Exception as e:
                print(f"Failed {url}: {e}")
        return f"Processed {count} Group Profiles."

    def infer_relationships_from_descriptions(self):
        groups = store.get_groups()
        tools = store.get_tools()
        count = 0
        for tool in tools:
            desc = tool.get('description', '').lower()
            if not desc: continue
            for group in groups:
                g_name = group['name'].lower()
                if re.search(r'\b' + re.escape(g_name) + r'\b', desc):
                    if tool['id'] not in group['tools']:
                        group['tools'].append(tool['id'])
                        count += 1
        store.save_data()
        return f"Inferred {count} relationships from Tool descriptions."

# --- UI Styling ---
def inject_custom_css():
    st.markdown("""
    <style>
    /* GLOBAL THEME: Professional Light */
    .stApp {
        background-color: #f8fafc; /* Slate-50 */
        color: #0f172a; /* Slate-900 */
        font-family: 'Inter', sans-serif;
    }
    
    /* SIDEBAR styling */
    section[data-testid="stSidebar"] {
        background-color: #ffffff;
        border-right: 1px solid #e2e8f0;
        box-shadow: 2px 0 5px rgba(0,0,0,0.02);
    }
    section[data-testid="stSidebar"] h1 {
        color: #1e293b;
        font-weight: 800;
        font-size: 1.5rem;
    }
    section[data-testid="stSidebar"] .stRadio label {
        color: #475569;
        font-weight: 500;
    }
    
    /* HEADERS */
    h1, h2, h3 {
        color: #1e293b;
        font-family: 'Inter', sans-serif;
        letter-spacing: -0.025em;
    }
    h1 { font-weight: 800; }
    h2 { font-weight: 700; }
    
    /* CARDS (Metrics & Visualizer Container) */
    div[data-testid="stMetric"], .graph-container {
        background-color: #ffffff;
        padding: 24px;
        border-radius: 12px;
        border: 1px solid #e2e8f0;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
    }
    div[data-testid="stMetricLabel"] {
        color: #64748b; /* Slate-500 */
        font-size: 0.875rem;
        font-weight: 500;
    }
    div[data-testid="stMetricValue"] {
        color: #0f172a; /* Slate-900 */
        font-weight: 700;
    }
    
    /* BUTTONS */
    .stButton button {
        background-color: #2563eb; /* Blue-600 */
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.5rem 1rem;
        font-weight: 500;
        transition: background-color 0.2s;
    }
    .stButton button:hover {
        background-color: #1d4ed8; /* Blue-700 */
        border: none;
        color: white;
    }
    .stButton button:focus {
        box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.3);
        color: white;
    }
    
    /* INPUTS */
    .stTextInput input, .stTextArea textarea, .stSelectbox div[data-baseweb="select"] {
        background-color: #ffffff;
        border: 1px solid #cbd5e1;
        border-radius: 8px;
        color: #0f172a;
    }
    
    /* DATAFRAMES */
    div[data-testid="stDataFrame"] {
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        overflow: hidden;
    }
    
    /* EXPANDERS */
    .streamlit-expanderHeader {
        background-color: #f1f5f9;
        color: #334155;
        border-radius: 8px;
        font-weight: 600;
    }
    div[data-testid="stExpander"] {
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        background-color: white;
    }
    
    /* ALERTS/INFO */
    .stAlert {
        border-radius: 8px;
        border: 1px solid transparent;
    }
    </style>
    """, unsafe_allow_html=True)

# --- Logic Functions ---

def generate_stix_bundle(export_scope="All", selected_ids=None):
    groups = store.get_groups()
    tools = store.get_tools()
    stix_objects = []
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    active_groups = groups
    active_tools = tools

    if export_scope == "Groups Only":
        active_tools = []
        if selected_ids:
            active_groups = [g for g in groups if g['id'] in selected_ids]
    elif export_scope == "Tools Only":
        active_groups = []
        if selected_ids:
            active_tools = [t for t in tools if t['id'] in selected_ids]
    elif export_scope == "Custom Selection":
        if selected_ids:
            active_groups = [g for g in groups if g['id'] in selected_ids]
            active_tools = [t for t in tools if t['id'] in selected_ids]

    valid_ids = set()

    # 1. Groups
    for g in active_groups:
        stix_objects.append({
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": f"intrusion-set--{uuid.uuid4()}",
            "created": timestamp,
            "modified": timestamp,
            "name": g['name'],
            "description": g.get('description', ''),
            "x_custom_id": g['id']
        })
        valid_ids.add(g['id'])

    # 2. Tools
    for t in active_tools:
        t_type = "malware" if "malware" in t.get('type','').lower() else "tool"
        stix_objects.append({
            "type": t_type,
            "spec_version": "2.1",
            "id": f"{t_type}--{uuid.uuid4()}",
            "created": timestamp,
            "modified": timestamp,
            "name": t['name'],
            "description": t.get('description', ''),
            "labels": [t.get('type', 'unknown')],
            "x_custom_id": t['id']
        })
        valid_ids.add(t['id'])

    # 3. Relationships
    for g in store.get_groups():
        if g['id'] not in valid_ids: continue
        group_stix_id = next((x['id'] for x in stix_objects if x.get('x_custom_id') == g['id']), None)
        
        for t_id in g.get('tools', []):
            if t_id in valid_ids:
                tool_stix_id = next((x['id'] for x in stix_objects if x.get('x_custom_id') == t_id), None)
                if group_stix_id and tool_stix_id:
                    stix_objects.append({
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": f"relationship--{uuid.uuid4()}",
                        "created": timestamp,
                        "modified": timestamp,
                        "relationship_type": "uses",
                        "source_ref": group_stix_id,
                        "target_ref": tool_stix_id
                    })

    final_objects = []
    for obj in stix_objects:
        obj_copy = obj.copy()
        if 'x_custom_id' in obj_copy:
            del obj_copy['x_custom_id']
        final_objects.append(obj_copy)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": final_objects
    }
    return json.dumps(bundle, indent=2)

# --- UI Components ---

def sidebar():
    st.sidebar.title("☠️ Ransomware Tool Matrix")
    
    # Inject Professional Theme
    inject_custom_css()

    page = st.sidebar.radio("Navigation", [
        "Dashboard", 
        "Visualizer", 
        "Threat Actors", 
        "Tools & Malware", 
        "Report Gen", 
        "Export STIX"
    ])
    
    st.sidebar.markdown("---")
    
    # Sync Button
    st.sidebar.subheader("Data Sync")
    if st.sidebar.button("Fetch Updates from GitHub"):
        ingestor = GitHubIngestor()
        with st.sidebar.status("Syncing Data..."):
            st.write("Fetching Tools CSV...")
            msg1 = ingestor.fetch_all_tools_csv()
            st.write(msg1)
            
            st.write("Scraping Category Markdowns...")
            msg2 = ingestor.fetch_category_markdowns()
            st.write(msg2)
            
            st.write("Processing Group Profiles...")
            msg3 = ingestor.fetch_group_profiles()
            st.write(msg3)
            
            st.write("Inferring Relationships...")
            msg4 = ingestor.infer_relationships_from_descriptions()
            st.write(msg4)
            
            store.save_data()
        st.sidebar.success("Database Updated!")
        st.rerun()

    st.sidebar.info(f"DB Stats: {len(store.get_groups())} Groups | {len(store.get_tools())} Tools")
    return page

def render_dashboard():
    st.title("Operational Dashboard")
    
    # --- Data Prep ---
    groups = store.get_groups()
    tools = store.get_tools()
    
    df_groups = pd.DataFrame(groups)
    df_tools = pd.DataFrame(tools)
    
    # --- Filters ---
    with st.expander("🔎 Dashboard Filters", expanded=True):
        col_f1, col_f2 = st.columns(2)
        
        # Filter 1: Threat Groups
        all_group_names = sorted(df_groups['name'].tolist()) if not df_groups.empty else []
        selected_groups = col_f1.multiselect("Filter by Threat Group", all_group_names)
        
        # Filter 2: Tool Categories
        all_categories = sorted(df_tools['type'].unique().tolist()) if not df_tools.empty else []
        if "Unknown" in all_categories: all_categories.remove("Unknown")
        selected_categories = col_f2.multiselect("Filter by Tool Category", all_categories)
    
    # --- Filtering Logic ---
    filtered_groups = groups
    filtered_tools = tools
    
    if selected_groups:
        filtered_groups = [g for g in groups if g['name'] in selected_groups]
    
    # Identify tools used by the filtered groups
    active_group_tool_ids = set()
    for g in filtered_groups:
        active_group_tool_ids.update(g.get('tools', []))
        
    if selected_categories:
        filtered_tools = [t for t in tools if t.get('type') in selected_categories]
    
    # Final Intersection: Tools in category AND used by selected groups
    # Note: If no groups selected, 'filtered_groups' is ALL groups, so 'active_group_tool_ids' includes all used tools.
    filtered_tools = [t for t in filtered_tools if t['id'] in active_group_tool_ids]
    
    # --- Metrics Calculations ---
    count_groups = len(filtered_groups)
    count_tools = len(filtered_tools)
    
    # Calculate relationships overlap
    filtered_tool_ids = set(t['id'] for t in filtered_tools)
    
    total_relationships = 0
    tool_usage_counts = {} 
    
    for g in filtered_groups:
        for t_id in g.get('tools', []):
            if t_id in filtered_tool_ids:
                total_relationships += 1
                tool_obj = next((t for t in filtered_tools if t['id'] == t_id), None)
                if tool_obj:
                    tool_usage_counts[tool_obj['name']] = tool_usage_counts.get(tool_obj['name'], 0) + 1

    # --- Scorecard Layout ---
    st.markdown("### 📊 Key Performance Indicators")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Active Groups", count_groups, delta=f"{len(groups)} Total")
    m2.metric("Available Tools", count_tools, delta=f"{len(tools)} Total")
    m3.metric("Observed Relationships", total_relationships)
    
    density = round(total_relationships / count_groups, 1) if count_groups > 0 else 0
    m4.metric("Avg Tools/Group", density)
    
    st.divider()
    
    # --- Charts Layout ---
    c1, c2 = st.columns([1, 1])
    
    # Chart 1: Tool Categories (Donut)
    with c1:
        st.subheader("🛠️ Tools by Category")
        if filtered_tools:
            cat_counts = {}
            for t in filtered_tools:
                cat = t.get('type', 'Unknown')
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
            
            df_cat = pd.DataFrame(list(cat_counts.items()), columns=['Category', 'Count'])
            if not df_cat.empty:
                # Use theme colors: Slate/Blue palette
                fig_pie = px.pie(df_cat, values='Count', names='Category', hole=0.4, 
                                 color_discrete_sequence=['#1e293b', '#334155', '#475569', '#64748b', '#94a3b8', '#cbd5e1'])
                fig_pie.update_layout(margin=dict(t=0, b=0, l=0, r=0), paper_bgcolor='rgba(0,0,0,0)')
                st.plotly_chart(fig_pie, use_container_width=True)
            else:
                st.info("No categorical data available.")
        else:
            st.info("No tools selected.")

    # Chart 2: Top Tools (Bar)
    with c2:
        st.subheader("🏆 Top Used Tools")
        if tool_usage_counts:
            df_usage = pd.DataFrame(list(tool_usage_counts.items()), columns=['Tool', 'Count'])
            df_usage = df_usage.sort_values('Count', ascending=True).tail(10) # Top 10
            
            fig_bar = px.bar(df_usage, x='Count', y='Tool', orientation='h', text='Count',
                             color='Count', color_continuous_scale='Blues') # Updated to Blues
            fig_bar.update_layout(xaxis_title=None, yaxis_title=None, showlegend=False,
                                  margin=dict(t=0, b=0, l=0, r=0), paper_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("No relationships found in current selection.")

def render_visualizer():
    st.title("Ransowmare Tool Matrix Visualiser")
    
    groups = store.get_groups()
    tools = store.get_tools()
    
    # 1. Filters
    with st.expander("🔎 Filter Graph", expanded=True):
        c1, c2, c3 = st.columns(3)
        
        all_groups = sorted([g['name'] for g in groups])
        selected_groups = c1.multiselect("Threat Actors", all_groups)
        
        all_cats = sorted(list(set(t.get('type', 'Unknown') for t in tools)))
        selected_cats = c2.multiselect("Tool Categories", all_cats)
        
        all_tools = sorted([t['name'] for t in tools])
        selected_tools = c3.multiselect("Tools / Malware", all_tools)

    # 2. Logic
    # Map for easy access
    tools_map = {t['id']: t for t in tools}
    
    # Determine valid IDs based on filters
    valid_group_ids = set(g['id'] for g in groups)
    if selected_groups:
        valid_group_ids = set(g['id'] for g in groups if g['name'] in selected_groups)
        
    valid_tool_ids = set(t['id'] for t in tools)
    if selected_cats:
        valid_tool_ids &= set(t['id'] for t in tools if t.get('type') in selected_cats)
    if selected_tools:
        valid_tool_ids &= set(t['id'] for t in tools if t['name'] in selected_tools)

    # 3. Build Graph
    nodes = []
    edges = []
    added_nodes = set()
    
    # We iterate groups and their relationships to define the graph
    for g in groups:
        # Skip if group itself is filtered out
        if g['id'] not in valid_group_ids:
            continue
            
        g_has_visible_connection = False
        
        for t_id in g.get('tools', []):
            if t_id in valid_tool_ids:
                g_has_visible_connection = True
                
                # Add Tool Node
                if t_id not in added_nodes:
                    t_obj = tools_map.get(t_id)
                    if t_obj:
                        icon = get_node_icon("tool", t_obj['name'])
                        nodes.append(Node(
                            id=t_id,
                            label=t_obj['name'],
                            size=20,
                            shape="image",
                            image=icon,
                            title=t_obj.get('description', '')
                        ))
                        added_nodes.add(t_id)
                        
                        # Add Category Node Link
                        cat = t_obj.get('type')
                        if cat and cat in ATTACK_PATTERN_NAMES:
                            if cat not in added_nodes:
                                cat_icon = get_node_icon("tool", cat)
                                nodes.append(Node(id=cat, label=cat, size=35, shape="image", image=cat_icon, color="#f59e0b"))
                                added_nodes.add(cat)
                            edges.append(Edge(source=t_id, target=cat, color="#cbd5e1", dashed=True))

                # Add Edge
                edges.append(Edge(source=g['id'], target=t_id, color="#64748b"))

        # Add Group Node (if connected or if explicitly selected and has no tools)
        if g_has_visible_connection or (selected_groups and not selected_cats and not selected_tools):
             if g['id'] not in added_nodes:
                icon = get_node_icon("group")
                nodes.append(Node(
                    id=g['id'],
                    label=g['name'],
                    size=30,
                    shape="image",
                    image=icon,
                    title=g.get('description', '')
                ))
                added_nodes.add(g['id'])

    # Config
    config = Config(
        width=1400, height=800, directed=True, 
        physics={"enabled": True, "stabilization": {"iterations": 200, "fit": True}, "barnesHut": {"gravitationalConstant": -3000, "springLength": 100}, "minVelocity": 0.75},
        nodeHighlightBehavior=True, highlightColor="#F7A7A6", collapsible=False,
        interaction={"hover": True, "navigationButtons": True, "zoomView": True, "multiselect": True, "dragNodes": True}
    )
    
    st.markdown('<div class="graph-container">', unsafe_allow_html=True)
    if not nodes:
        st.warning("No relationships found for the selected filters.")
        return None
    else:
        return agraph(nodes=nodes, edges=edges, config=config)
    st.markdown('</div>', unsafe_allow_html=True)

def render_groups():
    st.title("Threat Actors")
    
    with st.expander("➕ Add New Threat Group", expanded=False):
        with st.form("add_group_form"):
            name = st.text_input("Group Name")
            desc = st.text_area("Description")
            
            all_tools = store.get_tools()
            tool_options = {t['name']: t['id'] for t in all_tools}
            selected_tool_names = st.multiselect("Observed Tools", options=list(tool_options.keys()))
            
            submitted = st.form_submit_button("Create Group")
            if submitted and name:
                selected_ids = [tool_options[n] for n in selected_tool_names]
                store.upsert_group(name, desc, selected_tool_names)
                st.success(f"Added {name}")
                st.rerun()

    groups = store.get_groups()
    if not groups:
        st.info("No groups found.")
        
    for g in groups:
        with st.container():
            st.markdown(f"### {g['name']}")
            st.markdown(f"*{g.get('description', 'No description')}*")
            
            g_tools = [t for t in store.get_tools() if t['id'] in g.get('tools', [])]
            if g_tools:
                st.markdown("**Arsenal:** " + ", ".join([f"`{t['name']}`" for t in g_tools]))
            
            if st.button(f"Delete {g['name']}", key=f"del_{g['id']}"):
                store.delete_group(g['id'])
                st.rerun()
            st.divider()

def render_tools():
    st.title("Tools & Malware")
    
    with st.expander("➕ Add New Tool", expanded=False):
        with st.form("add_tool_form"):
            name = st.text_input("Tool Name")
            t_type = st.selectbox("Type", ["RMM", "C2 Framework", "Credential Access", "Exfiltration", "Defense Evasion", "Discovery", "Execution", "Other"])
            desc = st.text_area("Description")
            
            submitted = st.form_submit_button("Add Tool")
            if submitted and name:
                if store.upsert_tool(name, t_type, desc):
                    st.success(f"Added {name}")
                    st.rerun()
                else:
                    st.error("Invalid Tool Name (URL, Date, or Junk detected)")

    tools = store.get_tools()
    df = pd.DataFrame(tools)
    if not df.empty:
        col1, col2 = st.columns([3, 1])
        with col1:
            st.dataframe(df[["name", "type", "description"]], use_container_width=True, height=500)
        with col2:
            st.subheader("Deletion")
            tool_to_delete = st.selectbox("Select tool to delete", options=[""] + [t['name'] for t in tools])
            if tool_to_delete:
                if st.button(f"Confirm Delete"):
                    t_id = next(t['id'] for t in tools if t['name'] == tool_to_delete)
                    store.delete_tool(t_id)
                    st.rerun()

def render_report():
    st.title("Community Report Generator (YAML)")
    
    with st.form("report_form"):
        col1, col2 = st.columns(2)
        reporter = col1.text_input("Reporter Name/Handle", "Anonymous")
        date_str = col2.date_input("Date of Observation", datetime.now())
        tlp = st.selectbox("TLP Level", ["CLEAR", "GREEN", "AMBER", "RED"], index=0)
        
        st.markdown("---")
        groups = store.get_groups()
        tools = store.get_tools()
        
        group_options = ["New / Unknown"] + [g['name'] for g in groups]
        selected_group = st.selectbox("Observed Group", group_options)
        
        custom_group = ""
        if selected_group == "New / Unknown":
            custom_group = st.text_input("Enter Group Name")
        
        description = st.text_area("Brief Description of Activity")
        
        st.markdown("**Tools Observed**")
        selected_tool_names = st.multiselect("Select Tools", [t['name'] for t in tools])
        
        references = st.text_area("References (One URL per line)")
        
        submitted = st.form_submit_button("Generate YAML Report")
        
        if submitted:
            final_group = custom_group if selected_group == "New / Unknown" else selected_group
            yaml_output = f"""reporter: {reporter}
date: {date_str}
tlp: {tlp}
group: {final_group}
description: |
  {description.replace(chr(10), chr(10) + '  ')}
tools:"""
            for t_name in selected_tool_names:
                t = next((x for x in tools if x['name'] == t_name), None)
                cat = t['type'] if t else "Unknown"
                yaml_output += f"""
  - name: {t_name}
    category: {cat}"""

            if references:
                yaml_output += "\nreferences:"
                for ref in references.split('\n'):
                    if ref.strip():
                        yaml_output += f"\n  - {ref.strip()}"
            
            st.code(yaml_output, language="yaml")

def render_export():
    st.title("Export STIX 2.1 Bundle")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.subheader("Scope")
        scope = st.radio("Select Export Scope", ["All", "Groups Only", "Tools Only", "Custom Selection"])
        
    selected_ids = []
    with col2:
        if scope == "Groups Only":
            groups = store.get_groups()
            sel_names = st.multiselect("Select Groups", [g['name'] for g in groups], default=[g['name'] for g in groups])
            selected_ids = [g['id'] for g in groups if g['name'] in sel_names]
            
        elif scope == "Tools Only":
            tools = store.get_tools()
            sel_names = st.multiselect("Select Tools", [t['name'] for t in tools])
            selected_ids = [t['id'] for t in tools if t['name'] in sel_names]
            
        elif scope == "Custom Selection":
            groups = store.get_groups()
            tools = store.get_tools()
            sel_g = st.multiselect("Groups", [g['name'] for g in groups])
            sel_t = st.multiselect("Tools", [t['name'] for t in tools])
            
            selected_ids.extend([g['id'] for g in groups if g['name'] in sel_g])
            selected_ids.extend([t['id'] for t in tools if t['name'] in sel_t])

    if st.button("Generate Bundle", type="primary"):
        json_str = generate_stix_bundle(scope, selected_ids)
        st.download_button(
            label="Download .json Bundle",
            data=json_str,
            file_name=f"stix2_bundle_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
            mime="application/json"
        )
        st.success("Bundle generated.")

# --- Main Execution ---
def main():
    page = sidebar()
    
    if page == "Dashboard":
        render_dashboard()
    elif page == "Visualizer":
        render_visualizer()
    elif page == "Threat Actors":
        render_groups()
    elif page == "Tools & Malware":
        render_tools()
    elif page == "Report Gen":
        render_report()
    elif page == "Export STIX":
        render_export()

if __name__ == "__main__":
    main()
