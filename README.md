# AI Companion: Local LLM-Powered Burp Scans with Ollama

## Description
AI Companion enhances Burp Suite by using local large language models to analyze HTTP traffic. All analysis is performed through an Ollama host so your data never leaves your environment.

### AutoGuess Repeater Tab Name
<img width="1321" height="860" alt="image" src="https://github.com/user-attachments/assets/7940e976-b791-41c9-9506-00890a2e70fa" />

### Suggest Tests Based on Observed Items
<img width="1876" height="647" alt="image" src="https://github.com/user-attachments/assets/4fb99333-d151-4f27-b5a0-984645a35f31" />

## Features
- **Local AI Integration** with Ollama (e.g., `llama3`).
- **Auto-named Repeater Tabs** so requests are easier to track.
- **Context-aware Test Suggestions** for each request/response.
- **Persistent Settings** for prompts and host configuration.

## Prerequisites
- **Burp Suite Professional or Enterprise** (Community edition is not supported).
- **Ollama host** running locally (for example, `http://localhost:11434`).
- **Java 17** and **Apache Maven** if you wish to build from source.

## Installation
### Building from Source
```bash
git clone https://github.com/remot3/ai-auditor.git
cd ai-auditor
mvn clean package
```
The JAR will be created at `target/ai-auditor-1.0-SNAPSHOT-jar-with-dependencies.jar`.

### Loading the Extension
1. Open Burp Suite Professional or Enterprise.
2. Go to **Extensions** → **Add**, choose **Java**, and select the JAR.

## Usage
1. Open the **AI Companion** tab and enter your Ollama host. Click **Validate** to confirm connectivity.
2. (Optional) Provide custom instructions or a test prompt.
3. Right-click a request/response and choose **AI Companion** actions:
   - **Sugest Tests**
   - **Rename Repeater Tab**
4. Review findings in the **Notes** tab.

## Tips
- Avoid scanning very large responses—they may exceed token limits.
- Keep instructions clear and concise for the best results.

## License
This project is licensed under the GNU Affero General Public License v3.0.

## Disclaimer
AI Companion is provided *as is* for educational and testing purposes. Use it responsibly and in compliance with applicable laws.

