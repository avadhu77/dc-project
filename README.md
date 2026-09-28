# Security in Distributed Systems
## Simulation-Based Study of Cryptographic Protection, Access Control, Secure Communication, and Distributed Hashing

This project implements the M.Tech proposal as a Python-based simulation. It compares an unsecured distributed-system baseline with a security-enabled configuration under different node sizes and attack levels.

### Proposal coverage
- User authentication
- Role-based access control
- AES/Fernet encryption for protected messages
- Simulated secure-channel communication
- RSA digital signatures
- SHA-256 message integrity
- Consistent hashing for distributed data placement
- Controlled simulation of unauthorized access, message modification, replay, interception, and invalid authentication
- Metrics collection
- Experiment repetition and mean/std reporting
- CSV results and graphs
- Secure vs. unsecured comparison

### Project structure
```text
Security_Distributed_Systems/
├── main.py
├── config.py
├── distributed_system.py
├── security_modules.py
├── attack_simulator.py
├── metrics.py
├── experiment.py
├── requirements.txt
├── README.md
├── run_experiment.bat
└── results/
```

### Installation
Python 3.10+ is recommended.

```bash
pip install -r requirements.txt
```

### Run
```bash
python main.py
```

For a smaller quick run:
```bash
python main.py --quick
```

Results are written to:
- `results/experiment_results.csv`
- `results/summary_results.csv`
- `results/*.png`

### Research experiment
The default matrix follows the proposal:
- Nodes: 10, 25, 50, 100, 200
- Attack levels: 0%, 10%, 20%
- Configurations: unsecured and security-enabled
- Repetitions: configurable in `config.py`

The generated measurements include authentication time, authorization time, encryption/decryption time, hashing time, signature generation/verification, attack detection, unauthorized-access prevention, integrity detection, communication/computational overhead, data lookup time, execution time, and scalability indicators.

### Important note
This is an educational simulation, not a production distributed-security framework. "Secure channel" is represented with authenticated encryption primitives rather than deploying real network TLS sockets.
