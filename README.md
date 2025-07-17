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

## Prerequisites
### For General Usage
* **Operating System**: Windows, macOS, or Linux.
* **Ollama Host**: A running **Ollama** instance (e.g., `http://localhost:11434`)
* **Burp Suite Professional Edition** or **Burp Suite Enterprise Edition**
  * **NOTE**: Burp Suite Community Edition is currently not supported.

### Additional Requirements to Build from Source
* **Java Development Kit (JDK) 17** or later
* **Apache Maven**

## Installation
### Building from Source
#### Windows
1. Install JDK 17:
```
winget install Microsoft.OpenJDK.17
```
2. Install Apache Maven:
```
winget install Apache.Maven
```
3. Clone and Build:
```
git clone https://github.com/richeeta/ai-auditor.git
cd ai-auditor
mvn clean package
```
#### macOS
1. Install Homebrew:
```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```
2. Install JDK 17 and Maven:
```
brew install openjdk@17 maven
```
3. Clone and Build:
```
git clone https://github.com/richeeta/ai-auditor.git
cd ai-auditor
mvn clean package
```
#### Linux (Ubuntu/Debian)
1. Install JDK 17 and Maven:
```
sudo apt update
sudo apt install openjdk-17-jdk maven
```
2. Clone and Build:
```
git clone https://github.com/richeeta/ai-auditor.git
cd ai-auditor
mvn clean package
```

The compiled JAR will be available at `target/ai-auditor-1.0-SNAPSHOT-jar-with-dependencies.jar`.

## Installation: Loading JAR in Burp Suite (Recommended)
1. [Download](https://github.com/richeeta/AIAuditor/releases/tag/v1.0.1-pre) the latest version in **[Releases](https://github.com/richeeta/AIAuditor/releases/tag/v1.0.1-pre)**.
2. Open **Burp Suite Professional Edition** or **Burp Suite Enterprise Edition**.
3. Navigate to the **Extensions** tab.
4. Click **Add**, select **Java** as the extension type, and upload the `JAR` file.
5. Click **Next** to load the extension.

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

#### Analyze Selected Portion Only
1. In a request or a response, highlight what you want to scan.
2. Right-click on your highlighted selection.
3. Select **Extensions** > **AI Companion** > **Scan Selected Portion**.

### Review Results
Findings are displayed in Burp Scanner with detailed information.

## Usage Tips and Recommendations
### Avoid Scanning Large Responses
Large HTTP responses may exceed token limits and result in not only incomplete analysis but also degraded performance.

### Customize Instructions Effectively
To get the best results from the AI Companion, provide clear and specific instructions. For example:
* **Bad**: `Analyze and report everything that's bad security.`
* **Better**: `Identify and list all API endpoints found in the JavaScript file.`
* **Better**: `Only scan for XSS and SQLi. Do not scan for other issues.`

## FAQ
**Why isn’t Burp Suite Community Edition supported?**

AI Companion leans heavily on Burp Suite’s Scanner feature, and that’s a perk reserved for the Professional and Enterprise editions. Without it, the extension wouldn’t be able to tie findings neatly into Burp’s issue tracker or play nice with your existing workflows. It’s like trying to cook a gourmet meal on a campfire—it might work, but it won’t be pretty or efficient.

However, I am brainstorming ways to add support for Burp Suite Community Edition in the next release.


**Is this extension available in the BApp Store?**

Not yet—~~but it’s on the way (hopefully)~~! I submitted it to PortSwigger for review on December 2, 2024.

**UPDATE (12/17/24):** PortSwigger has sent me this response:

> Hi Richard,
> 
> Unfortunately, we're still looking into the best way forward to integrate AI/LLM features into extensions in Burp. For now, this means that we are not able to progress your BApp Store extension submission.
> 
> We are investigating different ways to help extension authors integrate this functionality into their extensions safely and securely. When we have further details to share, we'll make sure you're at the top of the list to know.
> Please let us know if you need any further assistance.
> 
> Cheers
> 
> `REDACTED FOR PRIVACY`
>
> PortSwigger

**What should I do if I encounter bugs or crashes?**

Please open a new issue. Include as much detail as possible—what you were doing, what went wrong, and any error messages you saw. The more I know, the faster I can fix it. Feedback is invaluable, and I genuinely appreciate users who take the time to report problems.

**Why are false positives or false negatives possible?**

AI models aren’t perfect—they’re probabilistic, not deterministic. This means they rely on patterns, probabilities, and sometimes a little educated guessing. Misinterpretations can happen, especially when instructions or context are vague. To minimize these hiccups, be specific in your instructions and provide clear, relevant data. The better the input, the sharper the output. Still, it’s always a good idea to double-check the findings before acting on them.

## Disclaimer

I am providing **AI Companion** *as-is* ***strictly*** for educational and testing purposes. By using this tool, you agree that you will do so in accordance with all applicable laws of whatever jurisdiction you're in and the terms of service for the APIs used. If you're a criminal, please don't use this tool.

## License

This project is licensed under the GNU Affero General Public License v3.0.

## Changelog & Known Issues

**NOTE**: This section will be moved into a separate changelog file with the next major release.

#### 12/17/2024: Known Issues in v1.0
* **KNOWN ISSUE**: AIAuditor may continue to make requests even if hitting rate limits.
* **KNOWN ISSUE**: Identical issues reported by same model may fail to deduplicate.
* **FEATURE REQUEST**: Support for locally hosted Mistral and LLaMa.

#### 12/2/2024: v1.0 released
* **FIXED**: Non-persistence of saved API keys has been addressed by replacing `PersistedObject` with `Preferences`.
* **IMPROVED**: Default instructions have been tweaked to exclude non-impactful issues and to ensure consistent JSON output that can be added to Scanner. 

#### 12/1/2024: `v1.0.1-preview` updated
* **ADDED**: Additional error handling.
* **KNOWN ISSUE**: Saved API keys may not persist across Burp sessions.

#### 11/29/2024: `v1.0.1-preview` released
* **ADDED**: Ability to scan selected portion of response.
* **FIXED (partially)**: some Scanner formatting issues.
