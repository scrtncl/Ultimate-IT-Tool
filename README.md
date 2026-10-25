# Ultimate-IT-Tool
**scrtncl** is an AI-powered IT operations platform that pairs a secure, local-first diagnostic desktop agent with a centralized web dashboard to discover, troubleshoot, and remediate network and system environments. Engineered for both personal use and multi-tenant professional IT, the architecture separates telemetry gathering from execution to ensure zero-trust, evidence-based remediation.

**Core Capabilities**

* **Automated Network Doctor:** Runs adaptive, multi-stage diagnostics spanning physical link layer checks, IP configuration, gateway reachability, and DNS resolution, functioning reliably even during complete internet outages.
* **Router Intelligence:** Utilizes a capability-based connector architecture to integrate with consumer and enterprise networking equipment via protocols like ICMP, SSH, SNMPv3, and vendor APIs to retrieve WAN status, interface counters, and client topology.
* **AI Technician:** Translates complex system telemetry into conversational insights. The AI operates through a strict tool policy gateway, executing only allowlisted diagnostic queries before proposing authorized, risk-calibrated repair plans.
* **Zero-Trust Infrastructure:** Maintains strict isolation between the cloud AI and local hardware. All operations require explicit authorization, short-lived approval tokens, and encrypted outbound connections to prevent unauthorized access to local networks.
