# Detailed Project Explanation

## 1. Project title
**Security in Distributed Systems: A Simulation-Based Study of Cryptographic Protection, Access Control, Secure Communication, and Distributed Hashing**

This title follows the proposal's focus on evaluating multiple security mechanisms together in one controlled distributed-system simulation.

## 2. What the project does
The program creates a virtual distributed system containing 10, 25, 50, 100, or 200 simulated nodes. It runs two main configurations:

1. **Unsecured baseline** – messages are transmitted without the additional security mechanisms.
2. **Security-enabled system** – authentication, access control, authenticated encryption, digital signatures, hashing, and distributed hashing are enabled.

The program then introduces controlled attack events and records security and performance measurements.

The proposal explicitly defines this baseline comparison and node-size experiment. See the proposal's baseline, workload, and experimental-design sections.

## 3. Architecture

```text
Experiment Configuration
        |
        v
Distributed System Model
        |
        +--> User / Node Management
        |
        +--> Authentication
        |
        +--> Access Control
        |
        +--> Secure Channel / Encryption
        |
        +--> Digital Signatures
        |
        +--> Cryptographic Hashing
        |
        +--> Distributed Hashing
        |
        v
Attack Simulator
        |
        v
Attack Detection
        |
        v
Metrics Collector
        |
        v
CSV + Graphs
        |
        v
Secure vs Unsecured Comparison
```

This corresponds to the architecture in the proposal.

## 4. Module explanation

### `distributed_system.py`
Creates simulated nodes and connects them logically through a consistent-hash ring. It exposes authentication, authorization, message send/receive, and data lookup operations.

### `security_modules.py`
Contains the security mechanisms:
- `AuthenticationManager`: username/password authentication.
- `AccessControl`: role-based permissions.
- `CryptoManager`: Fernet authenticated encryption.
- `DigitalSignature`: RSA-PSS signing and verification.
- `HashIntegrity`: SHA-256 digest creation and verification.
- `ConsistentHashRing`: distributes keys among nodes.

### `attack_simulator.py`
Generates non-destructive, controlled attack events:
- unauthorized access
- message modification
- replay attempts
- interception
- invalid authentication

The purpose is to measure detection/prevention rather than attack real systems.

### `metrics.py`
Stores experiment measurements and writes CSV files. It also calculates mean and standard deviation across repetitions.

### `experiment.py`
Runs the complete experimental matrix, collects metrics, creates summary tables, and generates graphs.

### `config.py`
Contains node sizes, attack levels, repetitions, workload size, and hash-ring settings.

## 5. Security mechanisms

### Authentication
The security-enabled configuration checks whether a supplied username/password pair is valid. Authentication time is measured in milliseconds.

### Access control
RBAC is used:
- admin: read/write/delete
- analyst: read/write
- viewer: read

An unknown user is not authorized in the secured configuration.

### Cryptographic protection
Fernet provides authenticated symmetric encryption for message confidentiality and integrity. The project records encryption and decryption time.

### Secure communication
The simulation represents a secure channel through encrypted, authenticated message packets. It does not claim to implement production TLS sockets.

### Digital signatures
RSA-PSS signatures are generated for protected messages and verified at the receiving side. A modified message should fail verification.

### Cryptographic hashing
SHA-256 is calculated for protected message payloads. The receiver recomputes the digest to identify modification.

### Distributed hashing
Consistent hashing maps a data key to one of the simulated nodes. Increasing the number of nodes allows lookup/scalability behavior to be studied.

## 6. Attack scenarios

### Unauthorized access
The simulation sends an access request from an unknown user. In the secured configuration the access-control layer blocks it.

### Message modification
A byte of the simulated packet is changed. Hash/signature verification is then used to detect the modification.

### Replay
A message identifier is stored in a seen-message set. A repeated identifier is treated as a replay event in the secured simulation.

### Interception
The experiment records whether a message is protected as ciphertext. The objective is to compare exposure of the payload between configurations.

### Invalid authentication
The attack generator represents invalid login attempts and records whether the secured authentication layer blocks them.

## 7. Experimental matrix

Default:
- Nodes = 10, 25, 50, 100, 200
- Attack level = 0%, 10%, 20%
- Configuration = unsecured/security-enabled
- Repetitions = 3

This reproduces the configuration matrix in the proposal and adds repetitions so mean and standard deviation can be reported.

## 8. Evaluation metrics

The program records:
- Authentication time
- Authorization time
- Encryption time
- Decryption time
- SHA-256 hashing time
- Digital signature generation time
- Signature verification time
- Attack detection rate
- Unauthorized access prevention rate
- Message-integrity detection rate
- Communication overhead
- Computational overhead
- False acceptance rate
- False rejection rate
- Distributed-hash lookup time
- Total execution time
- Number of attempted/detected attacks

## 9. Expected interpretation

The proposal expects security mechanisms to introduce computational/communication overhead while improving protection. The program is designed to test those expectations experimentally rather than hard-coding conclusions.

When you obtain the generated CSV files, use the actual measurements for the thesis results chapter. Do not replace measured values with expected values.

## 10. How to run

### Windows
1. Install Python 3.10 or newer.
2. Open the project folder in VS Code.
3. Open Terminal.
4. Run:
```bash
pip install -r requirements.txt
python main.py
```

### Google Colab
Upload the project files, install dependencies:
```python
!pip install cryptography numpy pandas matplotlib
```
Then run:
```python
!python main.py --quick
```

For the full experiment:
```python
!python main.py
```

## 11. Files generated
After execution:
- `results/experiment_results.csv` – every individual experiment.
- `results/summary_results.csv` – mean/std grouped results.
- PNG graphs – node scalability, attack detection, lookup time, overhead, and attack-level comparison.

## 12. Suggested M.Tech chapter mapping

### Chapter 1 – Introduction
Explain distributed systems, security threats, and the motivation for security mechanisms.

### Chapter 2 – Literature Review
Discuss distributed-system security, authentication, access control, cryptography, digital signatures, hashing, and distributed hashing.

### Chapter 3 – Problem Statement and Objectives
Use the proposal's stated problem, aim, objectives, research questions, and hypotheses.

### Chapter 4 – Methodology
Explain the simulator architecture, two configurations, attack model, node sizes, workload, and metrics.

### Chapter 5 – Implementation
Explain each Python module and security mechanism.

### Chapter 6 – Results and Analysis
Insert the actual CSV-derived tables and generated graphs. Discuss how node count and attack level affect security and performance.

### Chapter 7 – Conclusion and Future Work
Summarize findings based on measured data. Future work can include real multi-process deployment, real TLS sockets, larger node counts, stronger replay protection, and more realistic network-delay models.

## 13. Viva explanation in simple language

**What is your project?**
My project is a Python-based simulation of security mechanisms in a distributed system. It compares an unsecured system with a security-enabled system.

**Why simulation?**
A real distributed deployment with many machines is difficult to reproduce consistently. The proposal therefore uses a controlled Python simulation so that node size, workload, and attack conditions can be repeated.

**What security mechanisms are implemented?**
Authentication, role-based access control, encryption, simulated secure communication, RSA digital signatures, SHA-256 hashing, and consistent distributed hashing.

**What attacks are simulated?**
Unauthorized access, message modification, replay attempts, interception, and invalid authentication.

**What do you measure?**
Authentication/authorization time, encryption/decryption time, hashing/signature time, attack detection, unauthorized-access prevention, communication/computational overhead, lookup time, execution time, and scalability.

**What is the research contribution?**
The project evaluates multiple security mechanisms under common controlled conditions and studies the trade-off between security protection, computational cost, communication overhead, and scalability.
