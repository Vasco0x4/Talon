// Transport strings (User-Agent, Host, Endpoint) are XOR-obfuscated and
// decoded at runtime by ConfigDecode() in Core.c (arrays live there).
// Lab target: Havoc teamserver container (talon-lab TLS listener, port 9001)
#define CONFIG_PORT       9001
#define CONFIG_SECURE     TRUE
#define CONFIG_SLEEP      3
#define CONFIG_JITTER     40
