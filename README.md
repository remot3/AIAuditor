# AI Companion: Local LLM-Powered Burp Scans with Ollama

## Description
AI Companion is an extension for Burp Suite Professional and Enterprise editions that leverages locally hosted models through Ollama to enhance vulnerability scanning and analysis.

### AutoGuess repeater Tab name
<img width="1321" height="860" alt="image" src="https://github.com/user-attachments/assets/7940e976-b791-41c9-9506-00890a2e70fa" />

### Sugest tests based on observed items in Request/Response
<img width="1876" height="647" alt="image" src="https://github.com/user-attachments/assets/4fb99333-d151-4f27-b5a0-984645a35f31" />

## Features
### Core Capabilities
* **Local AI Integration**: Supports local models via **Ollama** (e.g., `llama3`)
* **Persistent Settings**: Custom instructions and Ollama host settings persist across sessions.


## Usage
### Initial Setup

1. Go to the AI Companion tab in Burp Suite.
2. Specify your Ollama host and click **Validate** to ensure it's reachable. The **Default** model will automatically use the local `llama3` model when an Ollama host is provided.
3. *Optional*: Add **Custom Instructions** to refine the analysis.
4. Save your settings.

### Analyzing Requests/Responses
#### Single Analysis
1. Right-click a request or response in Burp Suite.
2. Select **Extensions** > **AI Companion** > **Scan Full Request/Response**.


### Review Results
Findings are displayed in the Notes tab in the sidebar with detailed information.

## Usage Tips and Recommendations
### Avoid Scanning Large Responses
Large HTTP responses may exceed token limits and result in not only incomplete analysis but also degraded performance.

### Customize Instructions Effectively
To get the best results from the AI Companion, provide clear and specific instructions. For example:
* **Bad**: `Analyze and report everything that's bad security.`
* **Better**: `Identify and list all API endpoints found in the JavaScript file.`
* **Better**: `Only scan for XSS and SQLi. Do not scan for other issues.`

## License

This project is licensed under the GNU Affero General Public License v3.0.

