# GitleaksVerifier CLI

This project provides a command-line interface (CLI) tool to verify secrets found by gitleaks. It supports various secret types and provides options for verbosity, rule filtering, and output customization.

## Features

- Command-line argument parsing
- Logging configuration with colored output
- Error handling and proper exit codes
- Type hints for better code clarity
- Option to filter by specific rule ID
- JSON output with verification results
- Option to print only valid secrets

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/aydinnyunus/GitleaksVerifier.git
    cd GitleaksVerifier
    ```

2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Gitleaks Example

```bash
gitleaks git -f json -r secrets.json
```

Now you can use `secrets.json` file to verify secrets.

### Basic Usage

```bash
python main.py secrets.json
```

### Verbose Output

```bash
python main.py -v secrets.json
```

### Filter by Rule

```bash
python main.py -r github-token secrets.json
```

### Specify Output File

```bash
python main.py -o results.json secrets.json
```

### Print Only Valid Secrets

```bash
python main.py --only-valid secrets.json
```

### Show Help

```bash
python main.py --help
```

## Example Output

The output JSON file will have the following structure:

```json
[
  {
    "secret": "example_secret",
    "rule_id": "github-token",
    "valid": true
  },
  {
    "secret": "invalid_secret",
    "rule_id": "slack-token",
    "valid": false,
    "error": "HTTP 401: Unauthorized"
  }
]
```

## Logging

The CLI uses the `colorama` library to provide colored output for different log levels:

- **INFO**: Green
- **WARNING**: Yellow
- **ERROR**: Red
- **DEBUG**: Blue

It leverages verification methods from [streaak/keyhacks](https://github.com/streaak/keyhacks) for accurate validation.

## Contact

[<img target="_blank" src="https://img.icons8.com/bubbles/100/000000/linkedin.png" title="LinkedIn">](https://linkedin.com/in/yunus-ayd%C4%B1n-b9b01a18a/) [<img target="_blank" src="https://img.icons8.com/bubbles/100/000000/github.png" title="Github">](https://github.com/aydinnyunus/GitleaksVerifier) [<img target="_blank" src="https://img.icons8.com/bubbles/100/000000/instagram-new.png" title="Instagram">](https://instagram.com/aydinyunus_/) [<img target="_blank" src="https://img.icons8.com/bubbles/100/000000/twitter-squared.png" title="LinkedIn">](https://twitter.com/aydinnyunuss)


